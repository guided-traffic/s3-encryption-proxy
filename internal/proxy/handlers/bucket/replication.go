package bucket

import (
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gorilla/mux"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/request"
	"github.com/sirupsen/logrus"
)

// ReplicationHandler handles bucket replication operations
type ReplicationHandler struct {
	BaseSubResourceHandler
}

// NewReplicationHandler creates a new replication handler
func NewReplicationHandler(base BaseSubResourceHandler) *ReplicationHandler {
	return &ReplicationHandler{BaseSubResourceHandler: base}
}

// Handle handles bucket replication requests
func (h *ReplicationHandler) Handle(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	h.Logger.WithFields(logrus.Fields{
		"method": r.Method,
		"bucket": bucket,
	}).Debug("Handling bucket replication operation")

	switch r.Method {
	case http.MethodGet:
		h.handleGetBucketReplication(w, r, bucket)
	case http.MethodPut:
		h.handlePutBucketReplication(w, r, bucket)
	case http.MethodDelete:
		h.handleDeleteBucketReplication(w, r, bucket)
	default:
		h.ErrorWriter.WriteNotImplemented(w, "BucketReplication_"+r.Method)
	}
}

// handleGetBucketReplication gets bucket replication configuration
func (h *ReplicationHandler) handleGetBucketReplication(w http.ResponseWriter, r *http.Request, bucket string) {
	h.Logger.WithField("bucket", bucket).Debug("Getting bucket replication configuration")

	input := &s3.GetBucketReplicationInput{
		Bucket:              aws.String(bucket),
		ExpectedBucketOwner: request.ExpectedBucketOwner(r),
	}

	output, err := h.S3Backend.GetBucketReplication(r.Context(), input)
	if err != nil {
		h.ErrorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	h.XMLWriter.WriteS3Document(w, newReplicationConfigurationDocument(output.ReplicationConfiguration))
}

// handlePutBucketReplication sets bucket replication configuration
func (h *ReplicationHandler) handlePutBucketReplication(w http.ResponseWriter, _ *http.Request, bucket string) {
	h.Logger.WithField("bucket", bucket).Debug("Setting bucket replication configuration")

	// For now, return not implemented
	h.ErrorWriter.WriteNotImplemented(w, "PutBucketReplication")
}

// handleDeleteBucketReplication deletes bucket replication configuration
func (h *ReplicationHandler) handleDeleteBucketReplication(w http.ResponseWriter, r *http.Request, bucket string) {
	h.Logger.WithField("bucket", bucket).Debug("Deleting bucket replication configuration")

	input := &s3.DeleteBucketReplicationInput{
		Bucket:              aws.String(bucket),
		ExpectedBucketOwner: request.ExpectedBucketOwner(r),
	}

	if _, err := h.S3Backend.DeleteBucketReplication(r.Context(), input); err != nil {
		h.ErrorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
