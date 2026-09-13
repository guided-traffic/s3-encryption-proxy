package bucket

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gorilla/mux"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/request"
	"github.com/sirupsen/logrus"
)

// PolicyHandler handles bucket policy operations
type PolicyHandler struct {
	BaseSubResourceHandler
}

// NewPolicyHandler creates a new policy handler
func NewPolicyHandler(base BaseSubResourceHandler) *PolicyHandler {
	return &PolicyHandler{BaseSubResourceHandler: base}
}

// Handle handles bucket policy operations (?policy)
func (h *PolicyHandler) Handle(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	h.Logger.WithFields(logrus.Fields{
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
		h.ErrorWriter.WriteNotImplemented(w, "BucketPolicy_"+r.Method)
	}
}

// maxBucketPolicyBytes is the size S3 documents for a bucket policy document.
const maxBucketPolicyBytes = 20 * 1024

// handleGetPolicy handles GET bucket policy requests
func (h *PolicyHandler) handleGetPolicy(w http.ResponseWriter, r *http.Request, bucket string) {
	h.Logger.WithField("bucket", bucket).Debug("Getting bucket policy")

	input := &s3.GetBucketPolicyInput{
		Bucket:              aws.String(bucket),
		ExpectedBucketOwner: request.ExpectedBucketOwner(r),
	}

	output, err := h.S3Backend.GetBucketPolicy(r.Context(), input)
	if err != nil {
		h.ErrorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	// A bucket with no policy is a refusal, not an empty success: answering 200
	// with no body reports a policy the bucket does not have (ADR 0007 D1).
	if aws.ToString(output.Policy) == "" {
		h.ErrorWriter.WriteGenericError(w, http.StatusNotFound, "NoSuchBucketPolicy",
			"The bucket policy does not exist")
		return
	}

	// Policy response should be JSON
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write([]byte(*output.Policy)); err != nil {
		h.Logger.WithError(err).Error("Failed to write bucket policy response")
	}
}

// handlePutPolicy handles PUT bucket policy requests
func (h *PolicyHandler) handlePutPolicy(w http.ResponseWriter, r *http.Request, bucket string) {
	h.Logger.WithField("bucket", bucket).Debug("Setting bucket policy")

	// Refused on the declared length, before the body is read: a sub-resource
	// document is small and bounded, and buffering an arbitrary one first is
	// what ADR 0011 D5 forbids.
	if r.ContentLength > maxBucketPolicyBytes {
		h.ErrorWriter.WriteGenericError(w, http.StatusBadRequest, "EntityTooLarge",
			"The bucket policy exceeds the maximum size this proxy accepts")
		return
	}

	// Read the request body (JSON policy)
	body, err := h.RequestParser.ReadBody(r)
	if err != nil {
		h.ErrorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	// A body with no declared length is judged on what arrived.
	if len(body) > maxBucketPolicyBytes {
		h.ErrorWriter.WriteGenericError(w, http.StatusBadRequest, "EntityTooLarge",
			"The bucket policy exceeds the maximum size this proxy accepts")
		return
	}

	// Validate that body is not empty
	if len(body) == 0 {
		h.Logger.WithField("bucket", bucket).Error("Empty policy in request body")
		h.ErrorWriter.WriteGenericError(w, http.StatusBadRequest, "MalformedPolicy", "Request body cannot be empty for policy configuration")
		return
	}

	// Validate JSON format
	policyStr := strings.TrimSpace(string(body))
	var policy interface{}
	if err := json.Unmarshal([]byte(policyStr), &policy); err != nil {
		h.Logger.WithFields(logrus.Fields{
			"bucket": bucket,
			"error":  err,
		}).Error("Failed to parse policy JSON")
		h.ErrorWriter.WriteGenericError(w, http.StatusBadRequest, "MalformedPolicy", "Invalid JSON format")
		return
	}

	input := &s3.PutBucketPolicyInput{
		Bucket:              aws.String(bucket),
		ExpectedBucketOwner: request.ExpectedBucketOwner(r),
		Policy:              aws.String(policyStr),
	}

	_, err = h.S3Backend.PutBucketPolicy(r.Context(), input)
	if err != nil {
		h.ErrorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleDeletePolicy handles DELETE bucket policy requests
func (h *PolicyHandler) handleDeletePolicy(w http.ResponseWriter, r *http.Request, bucket string) {
	h.Logger.WithField("bucket", bucket).Debug("Deleting bucket policy")

	input := &s3.DeleteBucketPolicyInput{
		Bucket:              aws.String(bucket),
		ExpectedBucketOwner: request.ExpectedBucketOwner(r),
	}

	_, err := h.S3Backend.DeleteBucketPolicy(r.Context(), input)
	if err != nil {
		h.ErrorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
