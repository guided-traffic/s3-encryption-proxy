package bucket

import (
	"encoding/xml"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

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
	output, err := h.s3Backend.CreateBucket(r.Context(), input)
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
	_, err := h.s3Backend.DeleteBucket(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	// Success - no content response
	w.WriteHeader(http.StatusNoContent)

	h.logger.WithField("bucket", bucket).Debug("Bucket deleted successfully")
}

// handleHeadBucket answers HEAD /{bucket} with the real operation.
//
// It used to be a ListObjectsV2 with MaxKeys 0, which answers 200 for a bucket
// that does not exist: the backend short-circuits the listing before it checks
// that the bucket is there. It also asked for a permission a caller may not
// need — the error surface of a listing is not the error surface of a HEAD.
func (h *Handler) handleHeadBucket(w http.ResponseWriter, r *http.Request, bucket string) {
	h.logger.WithField("bucket", bucket).Debug("Getting bucket metadata")

	output, err := h.s3Backend.HeadBucket(r.Context(), &s3.HeadBucketInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	// The region a client reads here is the proxy's answer, not the backend's:
	// the development backend returns no region at all, so the configured one is
	// the normal path rather than a fallback for a corner case.
	region := ""
	if output != nil {
		region = aws.ToString(output.BucketRegion)
	}
	if region == "" && h.config != nil {
		region = h.config.S3Backend.Region
	}
	if region != "" {
		w.Header().Set("x-amz-bucket-region", region)
	}

	w.WriteHeader(http.StatusOK)
}
