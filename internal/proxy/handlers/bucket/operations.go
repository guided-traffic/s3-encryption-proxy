package bucket

import (
	"encoding/xml"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/request"
)

// handleCreateBucket handles creating a bucket (PUT /bucket)
func (h *Handler) handleCreateBucket(w http.ResponseWriter, r *http.Request, bucket string) {
	h.logger.WithField("bucket", bucket).Debug("Creating bucket")

	// Parse the request to build CreateBucketInput
	input := &s3.CreateBucketInput{
		Bucket: aws.String(bucket),
	}

	// The body is read unconditionally. Gating the read on a declared length let
	// a request that declares a digest and sends nothing reach the backend
	// unverified - the verifier only runs where the body is read.
	{
		body, err := h.requestParser.ReadBody(r)
		if err != nil {
			if h.errorWriter.WriteChecksumVerdict(w, err) {
				return
			}
			h.errorWriter.WriteS3Error(w, err, bucket, "")
			return
		}

		if len(body) > 0 {
			var createBucketConfig struct {
				LocationConstraint string `xml:"LocationConstraint"`
			}
			// A non-empty body that is not well-formed is refused, as S3 does.
			// Swallowing the decode error created the bucket in the proxy's own
			// region while the client had asked for another one.
			// #nosec G709 - encoding/xml resolves no external entities and errors
			// on an unknown one in strict mode.
			if err := xml.Unmarshal(body, &createBucketConfig); err != nil {
				h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "MalformedXML",
					"The XML you provided was not well-formed or did not validate against our published schema")
				return
			}
			if createBucketConfig.LocationConstraint != "" {
				input.CreateBucketConfiguration = &s3types.CreateBucketConfiguration{
					LocationConstraint: s3types.BucketLocationConstraint(createBucketConfig.LocationConstraint),
				}
			}
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
		Bucket:              aws.String(bucket),
		ExpectedBucketOwner: request.ExpectedBucketOwner(r),
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
		Bucket:              aws.String(bucket),
		ExpectedBucketOwner: request.ExpectedBucketOwner(r),
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
