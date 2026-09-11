package bucket

import (
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gorilla/mux"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/request"
	"github.com/sirupsen/logrus"
)

// VersioningHandler handles bucket versioning operations
type VersioningHandler struct {
	BaseSubResourceHandler
}

// NewVersioningHandler creates a new versioning handler
func NewVersioningHandler(base BaseSubResourceHandler) *VersioningHandler {
	return &VersioningHandler{BaseSubResourceHandler: base}
}

// Handle handles bucket versioning requests
func (h *VersioningHandler) Handle(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	h.Logger.WithFields(logrus.Fields{
		"method": r.Method,
		"bucket": bucket,
	}).Debug("Handling bucket versioning operation")

	switch r.Method {
	case http.MethodGet:
		h.handleGetBucketVersioning(w, r, bucket)
	case http.MethodPut:
		h.handlePutBucketVersioning(w, r, bucket)
	default:
		h.ErrorWriter.WriteNotImplemented(w, "BucketVersioning_"+r.Method)
	}
}

// handleGetBucketVersioning gets bucket versioning configuration
func (h *VersioningHandler) handleGetBucketVersioning(w http.ResponseWriter, r *http.Request, bucket string) {
	h.Logger.WithField("bucket", bucket).Debug("Getting bucket versioning configuration")

	input := &s3.GetBucketVersioningInput{
		Bucket:              aws.String(bucket),
		ExpectedBucketOwner: request.ExpectedBucketOwner(r),
	}

	output, err := h.S3Backend.GetBucketVersioning(r.Context(), input)
	if err != nil {
		h.ErrorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	h.XMLWriter.WriteS3Document(w, versioningConfigurationDocument{
		XMLNS:     s3Namespace,
		Status:    string(output.Status),
		MfaDelete: string(output.MFADelete),
	})
}

// handlePutBucketVersioning sets bucket versioning configuration
func (h *VersioningHandler) handlePutBucketVersioning(w http.ResponseWriter, r *http.Request, bucket string) {
	h.Logger.WithField("bucket", bucket).Debug("Setting bucket versioning configuration")

	// Read the request body
	body, err := h.RequestParser.ReadBody(r)
	if err != nil {
		h.ErrorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	input := &s3.PutBucketVersioningInput{
		Bucket:              aws.String(bucket),
		ExpectedBucketOwner: request.ExpectedBucketOwner(r),
	}

	// Parse versioning configuration from body
	// Note: For now, we'll let the S3 client handle the body parsing
	// In a more complete implementation, we'd parse the XML here
	if len(body) > 0 {
		// This would need proper XML parsing in a complete implementation
		h.ErrorWriter.WriteNotImplemented(w, "PutBucketVersioning with body parsing")
		return
	}

	if _, err := h.S3Backend.PutBucketVersioning(r.Context(), input); err != nil {
		h.ErrorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	w.WriteHeader(http.StatusOK)
}
