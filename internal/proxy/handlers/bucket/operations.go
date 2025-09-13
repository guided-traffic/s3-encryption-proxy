package bucket

import (
	"encoding/xml"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/utils"
)

// handleListObjects handles listing objects in a bucket (GET /bucket)
func (h *Handler) handleListObjects(w http.ResponseWriter, r *http.Request, bucket string) {
	h.logger.WithField("bucket", bucket).Debug("Listing objects in bucket")

	// Check if this is a ListObjectsV2 or ListObjects request
	query := r.URL.Query()

	if query.Get("list-type") == "2" {
		// ListObjectsV2
		input := &s3.ListObjectsV2Input{
			Bucket: aws.String(bucket),
		}

		// Add optional parameters
		if prefix := query.Get("prefix"); prefix != "" {
			input.Prefix = aws.String(prefix)
		}
		if delimiter := query.Get("delimiter"); delimiter != "" {
			input.Delimiter = aws.String(delimiter)
		}
		if maxKeys := query.Get("max-keys"); maxKeys != "" {
			// Parse maxKeys and set it
			// For now, skip parsing
		}
		if contToken := query.Get("continuation-token"); contToken != "" {
			input.ContinuationToken = aws.String(contToken)
		}

		output, err := h.s3Client.ListObjectsV2(r.Context(), input)
		if err != nil {
			utils.HandleS3Error(w, h.logger, err, "Failed to list objects", bucket, "")
			return
		}

		w.Header().Set("Content-Type", "application/xml")
		if err := xml.NewEncoder(w).Encode(output); err != nil {
			h.logger.WithError(err).Error("Failed to encode list objects response")
		}
	} else {
		// ListObjects
		input := &s3.ListObjectsInput{
			Bucket: aws.String(bucket),
		}

		// Add optional parameters
		if prefix := query.Get("prefix"); prefix != "" {
			input.Prefix = aws.String(prefix)
		}
		if delimiter := query.Get("delimiter"); delimiter != "" {
			input.Delimiter = aws.String(delimiter)
		}
		if marker := query.Get("marker"); marker != "" {
			input.Marker = aws.String(marker)
		}

		output, err := h.s3Client.ListObjects(r.Context(), input)
		if err != nil {
			utils.HandleS3Error(w, h.logger, err, "Failed to list objects", bucket, "")
			return
		}

		w.Header().Set("Content-Type", "application/xml")
		if err := xml.NewEncoder(w).Encode(output); err != nil {
			h.logger.WithError(err).Error("Failed to encode list objects response")
		}
	}
}

// handleCreateBucket handles creating a bucket (PUT /bucket)
func (h *Handler) handleCreateBucket(w http.ResponseWriter, r *http.Request, bucket string) {
	h.logger.WithField("bucket", bucket).Debug("Creating bucket")

	// For now, return not implemented since we typically don't need to create buckets
	// through the proxy (they exist on the backend)
	h.errorWriter.WriteNotImplemented(w, "CreateBucket")
}

// handleDeleteBucket handles deleting a bucket (DELETE /bucket)
func (h *Handler) handleDeleteBucket(w http.ResponseWriter, r *http.Request, bucket string) {
	h.logger.WithField("bucket", bucket).Debug("Deleting bucket")

	// For now, return not implemented since we typically don't delete buckets
	// through the proxy
	h.errorWriter.WriteNotImplemented(w, "DeleteBucket")
}

// handleHeadBucket handles bucket metadata requests (HEAD /bucket)
func (h *Handler) handleHeadBucket(w http.ResponseWriter, r *http.Request, bucket string) {
	h.logger.WithField("bucket", bucket).Debug("Getting bucket metadata")

	// For HEAD requests, we typically just need to check if the bucket exists
	// We can do this by trying to list objects with max-keys=0
	input := &s3.ListObjectsV2Input{
		Bucket:  aws.String(bucket),
		MaxKeys: aws.Int32(0), // Don't return any objects, just check existence
	}

	_, err := h.s3Client.ListObjectsV2(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	// Bucket exists
	w.WriteHeader(http.StatusOK)
}
