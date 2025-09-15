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

// ReplicationHandler handles bucket replication operations
type ReplicationHandler struct {
	s3Client      interfaces.S3ClientInterface
	logger        *logrus.Entry
	xmlWriter     *response.XMLWriter
	errorWriter   *response.ErrorWriter
	requestParser *request.Parser
}

// NewReplicationHandler creates a new replication handler
func NewReplicationHandler(
	s3Client interfaces.S3ClientInterface,
	logger *logrus.Entry,
	xmlWriter *response.XMLWriter,
	errorWriter *response.ErrorWriter,
	requestParser *request.Parser,
) *ReplicationHandler {
	return &ReplicationHandler{
		s3Client:      s3Client,
		logger:        logger,
		xmlWriter:     xmlWriter,
		errorWriter:   errorWriter,
		requestParser: requestParser,
	}
}

// Handle handles bucket replication requests
func (h *ReplicationHandler) Handle(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	h.logger.WithFields(logrus.Fields{
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
		h.errorWriter.WriteNotImplemented(w, "BucketReplication_"+r.Method)
	}
}

// handleGetBucketReplication gets bucket replication configuration
func (h *ReplicationHandler) handleGetBucketReplication(w http.ResponseWriter, r *http.Request, bucket string) {
	h.logger.WithField("bucket", bucket).Debug("Getting bucket replication configuration")

	input := &s3.GetBucketReplicationInput{
		Bucket: aws.String(bucket),
	}

	output, err := h.s3Client.GetBucketReplication(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	h.xmlWriter.WriteXML(w, output)
}

// handlePutBucketReplication sets bucket replication configuration
func (h *ReplicationHandler) handlePutBucketReplication(w http.ResponseWriter, _ *http.Request, bucket string) {
	h.logger.WithField("bucket", bucket).Debug("Setting bucket replication configuration")

	// For now, return not implemented
	h.errorWriter.WriteNotImplemented(w, "PutBucketReplication")
}

// handleDeleteBucketReplication deletes bucket replication configuration
func (h *ReplicationHandler) handleDeleteBucketReplication(w http.ResponseWriter, r *http.Request, bucket string) {
	h.logger.WithField("bucket", bucket).Debug("Deleting bucket replication configuration")

	input := &s3.DeleteBucketReplicationInput{
		Bucket: aws.String(bucket),
	}

	output, err := h.s3Client.DeleteBucketReplication(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	h.xmlWriter.WriteXML(w, output)
}
