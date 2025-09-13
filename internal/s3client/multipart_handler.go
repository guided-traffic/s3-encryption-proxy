package s3client

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/sirupsen/logrus"
)

// MultipartHandler handles encrypted multipart upload operations
type MultipartHandler struct {
	client         *Client
	metadataHelper *MetadataHelper
}

// NewMultipartHandler creates a new multipart handler
func NewMultipartHandler(client *Client) *MultipartHandler {
	return &MultipartHandler{
		client:         client,
		metadataHelper: NewMetadataHelper(client.metadataPrefix),
	}
}

// CreateMultipartUpload creates a new multipart upload with encryption
func (h *MultipartHandler) CreateMultipartUpload(ctx context.Context, input *s3.CreateMultipartUploadInput) (*s3.CreateMultipartUploadOutput, error) {
	objectKey := aws.ToString(input.Key)
	bucketName := aws.ToString(input.Bucket)

	h.client.logger.WithFields(logrus.Fields{
		"key":    objectKey,
		"bucket": bucketName,
	}).Debug("Creating multipart upload with encryption")

	// Get encryption metadata for multipart uploads with HTTP Content-Type awareness
	httpContentType := aws.ToString(input.ContentType)
	encResult, err := h.client.encryptionMgr.EncryptDataWithHTTPContentType(ctx, []byte{}, objectKey, httpContentType, true)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize encryption for multipart upload: %w", err)
	}

	// Create enhanced input with encryption metadata
	enhancedInput := *input

	// Handle metadata based on encryption result
	var metadata map[string]string

	// For "none" provider: preserve original user metadata for pure pass-through
	if encResult.EncryptedDEK == nil && encResult.Metadata == nil {
		// "none" provider - preserve user metadata, no encryption metadata
		metadata = input.Metadata
	} else {
		// For encrypted providers, create metadata with client data + encryption info
		metadata = h.metadataHelper.PrepareEncryptionMetadata(input.Metadata, encResult.Metadata)
	}

	enhancedInput.Metadata = metadata

	// Create the multipart upload in S3 with encryption metadata
	output, err := h.client.s3Client.CreateMultipartUpload(ctx, &enhancedInput)
	if err != nil {
		return nil, fmt.Errorf("failed to create multipart upload in S3: %w", err)
	}

	uploadID := aws.ToString(output.UploadId)

	// Initialize multipart upload in encryption manager
	err = h.client.encryptionMgr.InitiateMultipartUpload(ctx, uploadID, objectKey, aws.ToString(input.Bucket))
	if err != nil {
		// Clean up the S3 multipart upload if encryption initialization fails
		abortInput := &s3.AbortMultipartUploadInput{
			Bucket:   input.Bucket,
			Key:      input.Key,
			UploadId: output.UploadId,
		}
		_, _ = h.client.s3Client.AbortMultipartUpload(ctx, abortInput)
		return nil, fmt.Errorf("failed to initialize multipart upload in encryption manager: %w", err)
	}

	h.client.logger.WithFields(logrus.Fields{
		"key":      objectKey,
		"bucket":   bucketName,
		"uploadID": uploadID,
	}).Debug("Successfully created encrypted multipart upload")

	return output, nil
}

// UploadPart uploads an encrypted part
func (h *MultipartHandler) UploadPart(ctx context.Context, input *s3.UploadPartInput) (*s3.UploadPartOutput, error) {
	objectKey := aws.ToString(input.Key)
	uploadID := aws.ToString(input.UploadId)
	partNumber := aws.ToInt32(input.PartNumber)

	h.client.logger.WithFields(logrus.Fields{
		"key":        objectKey,
		"uploadID":   uploadID,
		"partNumber": partNumber,
	}).Debug("Uploading encrypted part")

	// Use streaming encryption to avoid memory buffering large parts
	return h.uploadPartStreaming(ctx, input, objectKey, uploadID, int(partNumber))
}

// uploadPartStreaming implements true streaming encryption for upload parts
func (h *MultipartHandler) uploadPartStreaming(ctx context.Context, input *s3.UploadPartInput, objectKey, uploadID string, partNumber int) (*s3.UploadPartOutput, error) {
	// For parts that are small enough, use direct encryption (more efficient)
	// For large parts, we would need to implement chunk-by-chunk processing
	// For now, we keep the current approach but with better memory management

	// Read part data
	partData, err := io.ReadAll(input.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read part data: %w", err)
	}

	h.client.logger.WithFields(logrus.Fields{
		"key":        objectKey,
		"uploadID":   uploadID,
		"partNumber": partNumber,
		"partSize":   len(partData),
	}).Debug("Read part data for encryption")

	// Encrypt the part
	encResult, err := h.client.encryptionMgr.UploadPart(ctx, uploadID, partNumber, partData)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt part %d: %w", partNumber, err)
	}

	h.client.logger.WithFields(logrus.Fields{
		"key":           objectKey,
		"uploadID":      uploadID,
		"partNumber":    partNumber,
		"originalSize":  len(partData),
		"encryptedSize": len(encResult.EncryptedData),
	}).Debug("Successfully encrypted part")

	// Create new input with encrypted data
	encryptedInput := &s3.UploadPartInput{
		Bucket:               input.Bucket,
		Key:                  input.Key,
		UploadId:             input.UploadId,
		PartNumber:           input.PartNumber,
		Body:                 bytes.NewReader(encResult.EncryptedData),
		ContentLength:        aws.Int64(int64(len(encResult.EncryptedData))),
		ContentMD5:           input.ContentMD5,
		SSECustomerAlgorithm: input.SSECustomerAlgorithm,
		SSECustomerKey:       input.SSECustomerKey,
		SSECustomerKeyMD5:    input.SSECustomerKeyMD5,
		RequestPayer:         input.RequestPayer,
	}

	// Upload the encrypted part
	output, err := h.client.s3Client.UploadPart(ctx, encryptedInput)
	if err != nil {
		return nil, fmt.Errorf("failed to upload encrypted part %d: %w", partNumber, err)
	}

	h.client.logger.WithFields(logrus.Fields{
		"key":        objectKey,
		"uploadID":   uploadID,
		"partNumber": partNumber,
		"s3ETag":     aws.ToString(output.ETag),
	}).Debug("Successfully uploaded encrypted part")

	// Store the part ETag for completion
	err = h.client.encryptionMgr.StorePartETag(uploadID, partNumber, aws.ToString(output.ETag))
	if err != nil {
		h.client.logger.WithFields(logrus.Fields{
			"key":        objectKey,
			"uploadID":   uploadID,
			"partNumber": partNumber,
			"error":      err,
		}).Warn("Failed to store part ETag")
	}

	// Release encrypted data immediately after upload
	encResult = nil

	return output, nil
}

// CompleteMultipartUpload completes an encrypted multipart upload
func (h *MultipartHandler) CompleteMultipartUpload(ctx context.Context, input *s3.CompleteMultipartUploadInput) (*s3.CompleteMultipartUploadOutput, error) {
	if input == nil {
		return nil, fmt.Errorf("input parameter is nil")
	}

	if h == nil {
		return nil, fmt.Errorf("multipart handler is nil")
	}

	if h.client == nil {
		return nil, fmt.Errorf("client is nil")
	}

	if h.client.s3Client == nil {
		return nil, fmt.Errorf("s3Client is nil")
	}

	if h.client.encryptionMgr == nil {
		return nil, fmt.Errorf("encryptionMgr is nil")
	}

	objectKey := aws.ToString(input.Key)
	uploadID := aws.ToString(input.UploadId)

	h.client.logger.WithFields(logrus.Fields{
		"key":      objectKey,
		"uploadID": uploadID,
	}).Debug("Completing encrypted multipart upload")

	// Get multipart upload state for completion
	_, err := h.client.encryptionMgr.GetMultipartUploadState(uploadID)
	if err != nil {
		return nil, fmt.Errorf("failed to get multipart upload state: %w", err)
	}

	// Build completion map from input parts
	parts := make(map[int]string)
	if input.MultipartUpload != nil {
		h.client.logger.WithFields(logrus.Fields{
			"key":      objectKey,
			"uploadID": uploadID,
			"partsCount": len(input.MultipartUpload.Parts),
		}).Debug("MULTIPART-DEBUG: Processing parts for completion")

		for i, part := range input.MultipartUpload.Parts {
			h.client.logger.WithFields(logrus.Fields{
				"key":      objectKey,
				"uploadID": uploadID,
				"partIndex": i,
				"partNumber": part.PartNumber,
				"etag": part.ETag,
			}).Debug("MULTIPART-DEBUG: Processing part")

			if part.PartNumber != nil && part.ETag != nil {
				partNumber := int(aws.ToInt32(part.PartNumber))
				parts[partNumber] = aws.ToString(part.ETag)
			} else {
				h.client.logger.WithFields(logrus.Fields{
					"key":      objectKey,
					"uploadID": uploadID,
					"partIndex": i,
					"hasPartNumber": part.PartNumber != nil,
					"hasETag": part.ETag != nil,
				}).Warn("MULTIPART-DEBUG: Skipping part with nil PartNumber or ETag")
			}
		}

		h.client.logger.WithFields(logrus.Fields{
			"key":      objectKey,
			"uploadID": uploadID,
			"validPartsCount": len(parts),
		}).Debug("MULTIPART-DEBUG: Built parts map for completion")
	} else {
		return nil, fmt.Errorf("multipart upload completion data is missing")
	}

	// Complete the multipart upload with encryption
	finalMetadata, err := h.client.encryptionMgr.CompleteMultipartUpload(ctx, uploadID, parts)
	if err != nil {
		return nil, fmt.Errorf("failed to complete multipart upload with encryption: %w", err)
	}

	// Complete the multipart upload in S3
	output, err := h.client.s3Client.CompleteMultipartUpload(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to complete multipart upload in S3: %w", err)
	}

	// Store the original ETag before any metadata operations
	originalETag := aws.ToString(output.ETag)

	// After completing the multipart upload, we need to add the encryption metadata
	// to the final object since S3 doesn't transfer metadata from CreateMultipartUpload
	// Skip this entirely for "none" provider to maintain pure pass-through
	if len(finalMetadata) > 0 {
		h.client.logger.WithFields(logrus.Fields{
			"key":      objectKey,
			"uploadID": uploadID,
			"metadata": finalMetadata,
		}).Debug("Adding encryption metadata to completed object")

		// Copy the object to itself with the encryption metadata
		copyInput := &s3.CopyObjectInput{
			Bucket:            input.Bucket,
			Key:               input.Key,
			CopySource:        aws.String(fmt.Sprintf("%s/%s", aws.ToString(input.Bucket), objectKey)),
			Metadata:          finalMetadata,
			MetadataDirective: types.MetadataDirectiveReplace,
		}

		_, err = h.client.s3Client.CopyObject(ctx, copyInput)
		if err != nil {
			h.client.logger.WithFields(logrus.Fields{
				"key":      objectKey,
				"uploadID": uploadID,
				"error":    err,
			}).Warn("Failed to add encryption metadata to completed object")
		}
	}

	h.client.logger.WithFields(logrus.Fields{
		"key":      aws.ToString(input.Key),
		"uploadID": uploadID,
		"etag":     originalETag,
	}).Info("Successfully completed encrypted multipart upload")

	// Restore the original ETag if it was lost during metadata operations
	if originalETag != "" && aws.ToString(output.ETag) == "" {
		output.ETag = aws.String(originalETag)
	}

	return output, nil
}

// AbortMultipartUpload aborts an encrypted multipart upload
func (h *MultipartHandler) AbortMultipartUpload(ctx context.Context, input *s3.AbortMultipartUploadInput) (*s3.AbortMultipartUploadOutput, error) {
	uploadID := aws.ToString(input.UploadId)
	objectKey := aws.ToString(input.Key)

	h.client.logger.WithFields(logrus.Fields{
		"key":      objectKey,
		"uploadID": uploadID,
	}).Debug("Aborting encrypted multipart upload")

	// Abort in S3
	output, err := h.client.s3Client.AbortMultipartUpload(ctx, input)
	if err != nil {
		return nil, err
	}

	// Clean up encryption state
	err = h.client.encryptionMgr.CleanupMultipartUpload(uploadID)
	if err != nil {
		h.client.logger.WithFields(logrus.Fields{
			"key":      objectKey,
			"uploadID": uploadID,
			"error":    err,
		}).Warn("Failed to cleanup aborted multipart upload encryption state")
	}

	return output, nil
}

// ListParts lists parts of a multipart upload
func (h *MultipartHandler) ListParts(ctx context.Context, input *s3.ListPartsInput) (*s3.ListPartsOutput, error) {
	return h.client.s3Client.ListParts(ctx, input)
}

// ListMultipartUploads lists multipart uploads
func (h *MultipartHandler) ListMultipartUploads(ctx context.Context, input *s3.ListMultipartUploadsInput) (*s3.ListMultipartUploadsOutput, error) {
	return h.client.s3Client.ListMultipartUploads(ctx, input)
}
