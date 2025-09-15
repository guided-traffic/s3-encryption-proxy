package bucket

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gorilla/mux"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/interfaces"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/request"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
	"github.com/sirupsen/logrus"
)

// PolicyHandler handles bucket policy operations
type PolicyHandler struct {
	s3Backend     interfaces.S3BackendInterface
	logger        *logrus.Entry
	xmlWriter     *response.XMLWriter
	errorWriter   *response.ErrorWriter
	requestParser *request.Parser
}

// NewPolicyHandler creates a new policy handler
func NewPolicyHandler(
	s3Backend interfaces.S3BackendInterface,
	logger *logrus.Entry,
	xmlWriter *response.XMLWriter,
	errorWriter *response.ErrorWriter,
	requestParser *request.Parser,
) *PolicyHandler {
	return &PolicyHandler{
		s3Backend:      s3Backend,
		logger:        logger,
		xmlWriter:     xmlWriter,
		errorWriter:   errorWriter,
		requestParser: requestParser,
	}
}

// Handle handles bucket policy operations (?policy)
func (h *PolicyHandler) Handle(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	h.logger.WithFields(logrus.Fields{
		"method": r.Method,
		"bucket": bucket,
	}).Debug("Handling bucket policy operation")

	switch r.Method {
	case http.MethodGet:
		h.handleGetPolicy(w, r, bucket)
	case http.MethodPut:
		h.handlePutPolicy(w, r, bucket)
	case http.MethodDelete:
		h.handleDeletePolicy(w, r, bucket)
	default:
		h.errorWriter.WriteNotImplemented(w, "BucketPolicy_"+r.Method)
	}
}

// handleGetPolicy handles GET bucket policy requests
func (h *PolicyHandler) handleGetPolicy(w http.ResponseWriter, r *http.Request, bucket string) {
	h.logger.WithField("bucket", bucket).Debug("Getting bucket policy")

	input := &s3.GetBucketPolicyInput{
		Bucket: aws.String(bucket),
	}

	output, err := h.s3Backend.GetBucketPolicy(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	// Policy response should be JSON
	w.Header().Set("Content-Type", "application/json")
	if output.Policy != nil {
		if _, err := w.Write([]byte(*output.Policy)); err != nil {
			h.logger.WithError(err).Error("Failed to write bucket policy response")
		}
	}
}

// handlePutPolicy handles PUT bucket policy requests
func (h *PolicyHandler) handlePutPolicy(w http.ResponseWriter, r *http.Request, bucket string) {
	h.logger.WithField("bucket", bucket).Debug("Setting bucket policy")

	// Read the request body (JSON policy)
	body, err := h.requestParser.ReadBody(r)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	// Validate that body is not empty
	if len(body) == 0 {
		h.logger.WithField("bucket", bucket).Error("Empty policy in request body")
		h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "MalformedPolicy", "Request body cannot be empty for policy configuration")
		return
	}

	// Validate JSON format
	policyStr := strings.TrimSpace(string(body))
	var policy interface{}
	if err := json.Unmarshal([]byte(policyStr), &policy); err != nil {
		h.logger.WithFields(logrus.Fields{
			"bucket": bucket,
			"error":  err,
		}).Error("Failed to parse policy JSON")
		h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "MalformedPolicy", "Invalid JSON format")
		return
	}

	input := &s3.PutBucketPolicyInput{
		Bucket: aws.String(bucket),
		Policy: aws.String(policyStr),
	}

	_, err = h.s3Backend.PutBucketPolicy(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleDeletePolicy handles DELETE bucket policy requests
func (h *PolicyHandler) handleDeletePolicy(w http.ResponseWriter, r *http.Request, bucket string) {
	h.logger.WithField("bucket", bucket).Debug("Deleting bucket policy")

	input := &s3.DeleteBucketPolicyInput{
		Bucket: aws.String(bucket),
	}

	_, err := h.s3Backend.DeleteBucketPolicy(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
