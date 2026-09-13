package bucket

import (
	"encoding/xml"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gorilla/mux"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/request"
	"github.com/sirupsen/logrus"
)

// LoggingHandler handles bucket logging operations
type LoggingHandler struct {
	BaseSubResourceHandler
}

// NewLoggingHandler creates a new logging handler
func NewLoggingHandler(base BaseSubResourceHandler) *LoggingHandler {
	return &LoggingHandler{BaseSubResourceHandler: base}
}

// Handle handles bucket logging operations (?logging)
func (h *LoggingHandler) Handle(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	h.Logger.WithFields(logrus.Fields{
		"method": r.Method,
		"bucket": bucket,
	}).Debug("Handling bucket logging operation")

	switch r.Method {
	case http.MethodGet:
		h.handleGetLogging(w, r, bucket)
	case http.MethodPut:
		h.handlePutLogging(w, r, bucket)
	case http.MethodDelete:
		h.handleDeleteLogging(w, r, bucket)
	default:
		h.ErrorWriter.WriteNotImplemented(w, "BucketLogging_"+r.Method)
	}
}

// handleGetLogging handles GET bucket logging requests
func (h *LoggingHandler) handleGetLogging(w http.ResponseWriter, r *http.Request, bucket string) {
	h.Logger.WithField("bucket", bucket).Debug("Getting bucket logging configuration")

	input := &s3.GetBucketLoggingInput{
		Bucket:              aws.String(bucket),
		ExpectedBucketOwner: request.ExpectedBucketOwner(r),
	}

	output, err := h.S3Backend.GetBucketLogging(r.Context(), input)
	if err != nil {
		h.ErrorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	h.XMLWriter.WriteS3Document(w, newBucketLoggingStatusDocument(output.LoggingEnabled))
}

// handlePutLogging handles PUT bucket logging requests
func (h *LoggingHandler) handlePutLogging(w http.ResponseWriter, r *http.Request, bucket string) {
	h.Logger.WithField("bucket", bucket).Debug("Setting bucket logging configuration")

	// Read the request body
	body, ok := h.readDocument(w, r, bucket)
	if !ok {
		return
	}

	// Validate that body is not empty
	if len(body) == 0 {
		h.Logger.WithField("bucket", bucket).Error("Empty logging configuration in request body")
		h.ErrorWriter.WriteGenericError(w, http.StatusBadRequest, "MalformedXML", "Request body cannot be empty for logging configuration")
		return
	}

	input := &s3.PutBucketLoggingInput{
		Bucket:              aws.String(bucket),
		ExpectedBucketOwner: request.ExpectedBucketOwner(r),
	}

	var doc bucketLoggingStatusDocument
	if err := xml.Unmarshal(body, &doc); err != nil { // #nosec G709 -- encoding/xml fills a fixed struct and resolves no entities
		h.Logger.WithError(err).WithField("bucket", bucket).Warn("Refusing a malformed logging document")
		h.ErrorWriter.WriteGenericError(w, http.StatusBadRequest, "MalformedXML",
			"The XML you provided was not well-formed or did not validate against our published schema")
		return
	}

	// A document with no <LoggingEnabled> disables logging, which is what S3 does
	// with the same body.
	input.BucketLoggingStatus = doc.bucketLoggingStatus()

	if _, err := h.S3Backend.PutBucketLogging(r.Context(), input); err != nil {
		h.ErrorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	w.WriteHeader(http.StatusOK)
}

// handleDeleteLogging handles DELETE bucket logging requests
func (h *LoggingHandler) handleDeleteLogging(w http.ResponseWriter, r *http.Request, bucket string) {
	h.Logger.WithField("bucket", bucket).Debug("Disabling bucket logging configuration")

	// To disable logging, we send an empty BucketLoggingStatus via PUT
	input := &s3.PutBucketLoggingInput{
		Bucket:              aws.String(bucket),
		ExpectedBucketOwner: request.ExpectedBucketOwner(r),
		BucketLoggingStatus: &types.BucketLoggingStatus{
			// Empty LoggingEnabled means logging is disabled
		},
	}

	_, err := h.S3Backend.PutBucketLogging(r.Context(), input)
	if err != nil {
		h.ErrorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
