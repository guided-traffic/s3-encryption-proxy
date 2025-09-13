package root

import (
	"encoding/xml"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/interfaces"
	"github.com/sirupsen/logrus"
)

// Handler handles root-level S3 operations
type Handler struct {
	s3Client interfaces.S3ClientInterface
	logger   logrus.FieldLogger
}

// NewHandler creates a new root handler
func NewHandler(s3Client interfaces.S3ClientInterface, logger logrus.FieldLogger) *Handler {
	return &Handler{
		s3Client: s3Client,
		logger:   logger,
	}
}

// HandleListBuckets handles list buckets requests - Pass-through to S3
func (h *Handler) HandleListBuckets(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("Handling list buckets request")

	// Use the S3 client to list buckets
	response, err := h.s3Client.ListBuckets(r.Context(), &s3.ListBucketsInput{})
	if err != nil {
		h.logger.WithError(err).Error("Failed to list buckets")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Set content type
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)

	// Marshal and write the response
	if err := xml.NewEncoder(w).Encode(response); err != nil {
		h.logger.WithError(err).Error("Failed to encode list buckets response")
	}
}
