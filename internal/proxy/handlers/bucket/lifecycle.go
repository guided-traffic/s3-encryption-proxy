package bucket

import (
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gorilla/mux"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/request"
	"github.com/sirupsen/logrus"
)

// LifecycleHandler handles bucket lifecycle operations
type LifecycleHandler struct {
	BaseSubResourceHandler
}

// NewLifecycleHandler creates a new lifecycle handler
func NewLifecycleHandler(base BaseSubResourceHandler) *LifecycleHandler {
	return &LifecycleHandler{BaseSubResourceHandler: base}
}

// Handle handles bucket lifecycle requests
func (h *LifecycleHandler) Handle(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	h.Logger.WithFields(logrus.Fields{
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
		h.ErrorWriter.WriteNotImplemented(w, "BucketLifecycle_"+r.Method)
	}
}

// handleGetBucketLifecycleConfiguration gets bucket lifecycle configuration
func (h *LifecycleHandler) handleGetBucketLifecycleConfiguration(w http.ResponseWriter, r *http.Request, bucket string) {
	h.Logger.WithField("bucket", bucket).Debug("Getting bucket lifecycle configuration")

	input := &s3.GetBucketLifecycleConfigurationInput{
		Bucket:              aws.String(bucket),
		ExpectedBucketOwner: request.ExpectedBucketOwner(r),
	}

	output, err := h.S3Backend.GetBucketLifecycleConfiguration(r.Context(), input)
	if err != nil {
		h.ErrorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	h.XMLWriter.WriteS3Document(w, newLifecycleConfigurationDocument(output.Rules))
}

// handlePutBucketLifecycleConfiguration sets bucket lifecycle configuration
func (h *LifecycleHandler) handlePutBucketLifecycleConfiguration(w http.ResponseWriter, r *http.Request, bucket string) {
	h.Logger.WithField("bucket", bucket).Debug("Setting bucket lifecycle configuration")

	// Read the request body
	body, ok := h.readDocument(w, r, bucket)
	if !ok {
		return
	}

	input := &s3.PutBucketLifecycleConfigurationInput{
		Bucket:              aws.String(bucket),
		ExpectedBucketOwner: request.ExpectedBucketOwner(r),
	}

	// Parse lifecycle configuration from body
	// Note: For now, we'll let the S3 client handle the body parsing
	// In a more complete implementation, we'd parse the XML here
	if len(body) > 0 {
		// This would need proper XML parsing in a complete implementation
		h.ErrorWriter.WriteNotImplemented(w, "PutBucketLifecycleConfiguration with body parsing")
		return
	}

	if _, err := h.S3Backend.PutBucketLifecycleConfiguration(r.Context(), input); err != nil {
		h.ErrorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	w.WriteHeader(http.StatusOK)
}

// handleDeleteBucketLifecycle deletes bucket lifecycle configuration
func (h *LifecycleHandler) handleDeleteBucketLifecycle(w http.ResponseWriter, r *http.Request, bucket string) {
	h.Logger.WithField("bucket", bucket).Debug("Deleting bucket lifecycle configuration")

	input := &s3.DeleteBucketLifecycleInput{
		Bucket:              aws.String(bucket),
		ExpectedBucketOwner: request.ExpectedBucketOwner(r),
	}

	if _, err := h.S3Backend.DeleteBucketLifecycle(r.Context(), input); err != nil {
		h.ErrorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
