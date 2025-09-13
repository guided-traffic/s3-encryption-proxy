package s3client

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// PassthroughHandler handles non-encrypted S3 operations
type PassthroughHandler struct {
	s3Client *s3.Client
}

// NewPassthroughHandler creates a new passthrough handler
func NewPassthroughHandler(s3Client *s3.Client) *PassthroughHandler {
	return &PassthroughHandler{
		s3Client: s3Client,
	}
}

// ListObjects lists objects in a bucket
func (h *PassthroughHandler) ListObjects(ctx context.Context, input *s3.ListObjectsInput) (*s3.ListObjectsOutput, error) {
	return h.s3Client.ListObjects(ctx, input)
}

// ListObjectsV2 lists objects in a bucket using the V2 API
func (h *PassthroughHandler) ListObjectsV2(ctx context.Context, input *s3.ListObjectsV2Input) (*s3.ListObjectsV2Output, error) {
	return h.s3Client.ListObjectsV2(ctx, input)
}

// DeleteObjects deletes multiple objects
func (h *PassthroughHandler) DeleteObjects(ctx context.Context, input *s3.DeleteObjectsInput) (*s3.DeleteObjectsOutput, error) {
	return h.s3Client.DeleteObjects(ctx, input)
}

// GetObjectAcl retrieves object ACL
func (h *PassthroughHandler) GetObjectAcl(ctx context.Context, input *s3.GetObjectAclInput) (*s3.GetObjectAclOutput, error) {
	return h.s3Client.GetObjectAcl(ctx, input)
}

// PutObjectAcl sets object ACL
func (h *PassthroughHandler) PutObjectAcl(ctx context.Context, input *s3.PutObjectAclInput) (*s3.PutObjectAclOutput, error) {
	return h.s3Client.PutObjectAcl(ctx, input)
}

// GetObjectTagging retrieves object tags
func (h *PassthroughHandler) GetObjectTagging(ctx context.Context, input *s3.GetObjectTaggingInput) (*s3.GetObjectTaggingOutput, error) {
	return h.s3Client.GetObjectTagging(ctx, input)
}

// PutObjectTagging sets object tags
func (h *PassthroughHandler) PutObjectTagging(ctx context.Context, input *s3.PutObjectTaggingInput) (*s3.PutObjectTaggingOutput, error) {
	return h.s3Client.PutObjectTagging(ctx, input)
}

// DeleteObjectTagging deletes object tags
func (h *PassthroughHandler) DeleteObjectTagging(ctx context.Context, input *s3.DeleteObjectTaggingInput) (*s3.DeleteObjectTaggingOutput, error) {
	return h.s3Client.DeleteObjectTagging(ctx, input)
}

// GetObjectLegalHold retrieves object legal hold
func (h *PassthroughHandler) GetObjectLegalHold(ctx context.Context, input *s3.GetObjectLegalHoldInput) (*s3.GetObjectLegalHoldOutput, error) {
	return h.s3Client.GetObjectLegalHold(ctx, input)
}

// PutObjectLegalHold sets object legal hold
func (h *PassthroughHandler) PutObjectLegalHold(ctx context.Context, input *s3.PutObjectLegalHoldInput) (*s3.PutObjectLegalHoldOutput, error) {
	return h.s3Client.PutObjectLegalHold(ctx, input)
}

// GetObjectRetention retrieves object retention
func (h *PassthroughHandler) GetObjectRetention(ctx context.Context, input *s3.GetObjectRetentionInput) (*s3.GetObjectRetentionOutput, error) {
	return h.s3Client.GetObjectRetention(ctx, input)
}

// PutObjectRetention sets object retention
func (h *PassthroughHandler) PutObjectRetention(ctx context.Context, input *s3.PutObjectRetentionInput) (*s3.PutObjectRetentionOutput, error) {
	return h.s3Client.PutObjectRetention(ctx, input)
}

// GetObjectTorrent retrieves object torrent
func (h *PassthroughHandler) GetObjectTorrent(ctx context.Context, input *s3.GetObjectTorrentInput) (*s3.GetObjectTorrentOutput, error) {
	return h.s3Client.GetObjectTorrent(ctx, input)
}

// SelectObjectContent performs S3 Select
func (h *PassthroughHandler) SelectObjectContent(ctx context.Context, input *s3.SelectObjectContentInput) (*s3.SelectObjectContentOutput, error) {
	// TODO: Add encryption support for S3 Select
	return h.s3Client.SelectObjectContent(ctx, input)
}
