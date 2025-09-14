package bucket

import (
	"encoding/xml"
	"net/http"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
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
			if maxKeysInt, err := strconv.Atoi(maxKeys); err == nil && maxKeysInt > 0 && maxKeysInt <= 1000 {
				input.MaxKeys = aws.Int32(int32(maxKeysInt)) // #nosec G109 - range validated
			}
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

	// Parse the request to build CreateBucketInput
	input := &s3.CreateBucketInput{
		Bucket: aws.String(bucket),
	}

	// Parse location constraint if provided in request body
	if r.ContentLength > 0 {
		var createBucketConfig struct {
			LocationConstraint string `xml:"LocationConstraint"`
		}

		if err := xml.NewDecoder(r.Body).Decode(&createBucketConfig); err == nil {
			if createBucketConfig.LocationConstraint != "" {
				input.CreateBucketConfiguration = &s3types.CreateBucketConfiguration{
					LocationConstraint: s3types.BucketLocationConstraint(createBucketConfig.LocationConstraint),
				}
			}
		}
		if err := r.Body.Close(); err != nil {
			h.logger.WithError(err).Debug("Failed to close request body")
		}
	}

	// Copy relevant headers
	if cannedACL := r.Header.Get("x-amz-acl"); cannedACL != "" {
		input.ACL = s3types.BucketCannedACL(cannedACL)
	}

	if grantFullControl := r.Header.Get("x-amz-grant-full-control"); grantFullControl != "" {
		input.GrantFullControl = aws.String(grantFullControl)
	}

	if grantRead := r.Header.Get("x-amz-grant-read"); grantRead != "" {
		input.GrantRead = aws.String(grantRead)
	}

	if grantReadACP := r.Header.Get("x-amz-grant-read-acp"); grantReadACP != "" {
		input.GrantReadACP = aws.String(grantReadACP)
	}

	if grantWrite := r.Header.Get("x-amz-grant-write"); grantWrite != "" {
		input.GrantWrite = aws.String(grantWrite)
	}

	if grantWriteACP := r.Header.Get("x-amz-grant-write-acp"); grantWriteACP != "" {
		input.GrantWriteACP = aws.String(grantWriteACP)
	}

	// Create the bucket
	output, err := h.s3Client.CreateBucket(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	// Set response headers
	w.Header().Set("Content-Type", "application/xml")

	if output.Location != nil {
		w.Header().Set("Location", *output.Location)
	}

	w.WriteHeader(http.StatusOK)

	h.logger.WithField("bucket", bucket).Debug("Bucket created successfully")
}

// handleDeleteBucket handles deleting a bucket (DELETE /bucket)
func (h *Handler) handleDeleteBucket(w http.ResponseWriter, r *http.Request, bucket string) {
	h.logger.WithField("bucket", bucket).Debug("Deleting bucket")

	// Create the DeleteBucketInput
	input := &s3.DeleteBucketInput{
		Bucket: aws.String(bucket),
	}

	// Copy relevant headers
	if expectedBucketOwner := r.Header.Get("x-amz-expected-bucket-owner"); expectedBucketOwner != "" {
		input.ExpectedBucketOwner = aws.String(expectedBucketOwner)
	}

	// Delete the bucket
	_, err := h.s3Client.DeleteBucket(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	// Success - no content response
	w.WriteHeader(http.StatusNoContent)

	h.logger.WithField("bucket", bucket).Debug("Bucket deleted successfully")
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
