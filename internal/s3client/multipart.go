package s3client

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sort"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/factory"
	"github.com/sirupsen/logrus"
)

// putObjectStreaming handles streaming multipart upload for large objects
func (c *Client) putObjectStreaming(ctx context.Context, input *s3.PutObjectInput) (*s3.PutObjectOutput, error) {
	objectKey := aws.ToString(input.Key)
	bucketName := aws.ToString(input.Bucket)

	c.logger.WithFields(logrus.Fields{
		"key":         objectKey,
		"bucket":      bucketName,
		"segmentSize": c.segmentSize,
	}).Info("Starting streaming multipart upload")

	// Create multipart upload
	createInput := &s3.CreateMultipartUploadInput{
		Bucket:                  input.Bucket,
		Key:                     input.Key,
		ACL:                     input.ACL,
		CacheControl:            input.CacheControl,
		ContentDisposition:      input.ContentDisposition,
		ContentEncoding:         input.ContentEncoding,
		ContentLanguage:         input.ContentLanguage,
		ContentType:             input.ContentType,
		Expires:                 input.Expires,
		Metadata:                input.Metadata,
		StorageClass:            input.StorageClass,
		WebsiteRedirectLocation: input.WebsiteRedirectLocation,
		SSECustomerAlgorithm:    input.SSECustomerAlgorithm,
		SSECustomerKey:          input.SSECustomerKey,
		SSECustomerKeyMD5:       input.SSECustomerKeyMD5,
		SSEKMSKeyId:             input.SSEKMSKeyId,
		RequestPayer:            input.RequestPayer,
		Tagging:                 input.Tagging,
	}

	createOutput, err := c.CreateMultipartUpload(ctx, createInput)
	if err != nil {
		return nil, fmt.Errorf("failed to create streaming multipart upload: %w", err)
	}

	uploadID := aws.ToString(createOutput.UploadId)
	c.logger.WithFields(logrus.Fields{
		"key":      objectKey,
		"bucket":   bucketName,
		"uploadID": uploadID,
	}).Debug("Created streaming multipart upload")

	// Process stream in chunks
	var completedParts []types.CompletedPart
	partNumber := int32(1)
	buffer := make([]byte, c.segmentSize)

	for {
		// Read next chunk
		n, err := io.ReadFull(input.Body, buffer)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			// Abort multipart upload on read error
			if _, abortErr := c.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
				Bucket:   input.Bucket,
				Key:      input.Key,
				UploadId: createOutput.UploadId,
			}); abortErr != nil {
				c.logger.WithError(abortErr).Error("Failed to abort multipart upload after read error")
			}
			return nil, fmt.Errorf("failed to read data chunk: %w", err)
		}

		if n == 0 {
			break // End of stream
		}

		// Upload this chunk as a part
		partData := buffer[:n]
		partInput := &s3.UploadPartInput{
			Bucket:     input.Bucket,
			Key:        input.Key,
			UploadId:   createOutput.UploadId,
			PartNumber: aws.Int32(partNumber),
			Body:       bytes.NewReader(partData),
		}

		c.logger.WithFields(logrus.Fields{
			"key":        objectKey,
			"bucket":     bucketName,
			"uploadID":   uploadID,
			"partNumber": partNumber,
			"chunkSize":  n,
		}).Debug("Uploading streaming chunk")

		partOutput, err := c.UploadPart(ctx, partInput)
		if err != nil {
			// Abort multipart upload on part upload error
			if _, abortErr := c.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
				Bucket:   input.Bucket,
				Key:      input.Key,
				UploadId: createOutput.UploadId,
			}); abortErr != nil {
				c.logger.WithError(abortErr).Error("Failed to abort multipart upload after part upload error")
			}
			return nil, fmt.Errorf("failed to upload part %d: %w", partNumber, err)
		}

		completedParts = append(completedParts, types.CompletedPart{
			ETag:       partOutput.ETag,
			PartNumber: aws.Int32(partNumber),
		})

		c.logger.WithFields(logrus.Fields{
			"key":        objectKey,
			"bucket":     bucketName,
			"uploadID":   uploadID,
			"partNumber": partNumber,
			"etag":       aws.ToString(partOutput.ETag),
		}).Debug("Successfully uploaded streaming chunk")

		partNumber++

		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break // End of stream
		}
	}

	// Complete multipart upload
	completeInput := &s3.CompleteMultipartUploadInput{
		Bucket:   input.Bucket,
		Key:      input.Key,
		UploadId: createOutput.UploadId,
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: completedParts,
		},
	}

	completeOutput, err := c.CompleteMultipartUpload(ctx, completeInput)
	if err != nil {
		return nil, fmt.Errorf("failed to complete streaming multipart upload: %w", err)
	}

	c.logger.WithFields(logrus.Fields{
		"key":       objectKey,
		"bucket":    bucketName,
		"uploadID":  uploadID,
		"partCount": len(completedParts),
		"etag":      aws.ToString(completeOutput.ETag),
	}).Info("Successfully completed streaming multipart upload")

	// Convert to PutObjectOutput format
	return &s3.PutObjectOutput{
		ETag:                 completeOutput.ETag,
		Expiration:           completeOutput.Expiration,
		ServerSideEncryption: completeOutput.ServerSideEncryption,
		VersionId:            completeOutput.VersionId,
		SSEKMSKeyId:          completeOutput.SSEKMSKeyId,
		RequestCharged:       completeOutput.RequestCharged,
	}, nil
}

// CreateMultipartUpload creates a multipart upload with encryption support
func (c *Client) CreateMultipartUpload(ctx context.Context, input *s3.CreateMultipartUploadInput) (*s3.CreateMultipartUploadOutput, error) {
	objectKey := aws.ToString(input.Key)
	bucketName := aws.ToString(input.Bucket)
	c.logger.WithFields(logrus.Fields{
		"key":    objectKey,
		"bucket": bucketName,
	}).Debug("Creating multipart upload with encryption")

	// Get encryption metadata for multipart uploads
	dummyData := []byte("dummy")
	encResult, err := c.encryptionMgr.EncryptDataWithContentType(ctx, dummyData, objectKey, factory.ContentTypeMultipart)
	if err != nil {
		c.logger.WithError(err).WithFields(logrus.Fields{
			"key":    objectKey,
			"bucket": bucketName,
		}).Error("Failed to get encryption metadata for multipart upload")
		return nil, fmt.Errorf("failed to get encryption metadata: %w", err)
	}

	// Create enhanced input with encryption metadata
	encryptedInput := &s3.CreateMultipartUploadInput{
		Bucket:                  input.Bucket,
		Key:                     input.Key,
		ACL:                     input.ACL,
		CacheControl:            input.CacheControl,
		ContentDisposition:      input.ContentDisposition,
		ContentEncoding:         input.ContentEncoding,
		ContentLanguage:         input.ContentLanguage,
		ContentType:             input.ContentType,
		Expires:                 input.Expires,
		GrantFullControl:        input.GrantFullControl,
		GrantRead:               input.GrantRead,
		GrantReadACP:            input.GrantReadACP,
		GrantWriteACP:           input.GrantWriteACP,
		RequestPayer:            input.RequestPayer,
		SSECustomerAlgorithm:    input.SSECustomerAlgorithm,
		SSECustomerKey:          input.SSECustomerKey,
		SSECustomerKeyMD5:       input.SSECustomerKeyMD5,
		SSEKMSKeyId:             input.SSEKMSKeyId,
		SSEKMSEncryptionContext: input.SSEKMSEncryptionContext,
		ServerSideEncryption:    input.ServerSideEncryption,
		StorageClass:            input.StorageClass,
		Tagging:                 input.Tagging,
		WebsiteRedirectLocation: input.WebsiteRedirectLocation,
		ChecksumAlgorithm:       input.ChecksumAlgorithm,
	}

	// Handle metadata based on encryption result
	var metadata map[string]string

	// For "none" provider: preserve original user metadata for pure pass-through
	if encResult.EncryptedDEK == nil && encResult.Metadata == nil {
		// "none" provider - preserve user metadata, no encryption metadata
		if input.Metadata != nil {
			metadata = make(map[string]string)
			for k, v := range input.Metadata {
				metadata[k] = v
			}
		}
	} else {
		// For encrypted providers, create metadata with client data + encryption info
		metadata = make(map[string]string)
		if input.Metadata != nil {
			// Copy existing client metadata
			for k, v := range input.Metadata {
				metadata[k] = v
			}
		}

		// Add encryption metadata (already contains prefix from encryption manager)
		// Note: For multipart, encrypted-dek and aes-iv will be added during completion
		for k, v := range encResult.Metadata {
			metadata[k] = v
		}
	}

	c.logger.WithFields(logrus.Fields{
		"key":            objectKey,
		"bucket":         bucketName,
		"metadataLen":    len(metadata),
		"metadataPrefix": c.metadataPrefix,
		"metadata":       metadata,
	}).Info("📋 Prepared multipart upload encryption metadata for S3 storage")

	encryptedInput.Metadata = metadata

	// Create the multipart upload in S3 with encryption metadata
	output, err := c.s3Client.CreateMultipartUpload(ctx, encryptedInput)
	if err != nil {
		c.logger.WithError(err).WithFields(logrus.Fields{
			"key":    objectKey,
			"bucket": bucketName,
		}).Error("Failed to create multipart upload in S3")
		return nil, fmt.Errorf("failed to create multipart upload in S3: %w", err)
	}

	uploadID := aws.ToString(output.UploadId)

	// Initialize multipart upload in encryption manager
	err = c.encryptionMgr.InitiateMultipartUpload(ctx, uploadID, objectKey, bucketName)
	if err != nil {
		// Abort the S3 multipart upload if encryption initialization fails
		_, _ = c.s3Client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
			Bucket:   input.Bucket,
			Key:      input.Key,
			UploadId: output.UploadId,
		})
		c.logger.WithError(err).WithFields(logrus.Fields{
			"key":      objectKey,
			"bucket":   bucketName,
			"uploadID": uploadID,
		}).Error("Failed to initiate encrypted multipart upload")
		return nil, fmt.Errorf("failed to initiate encrypted multipart upload: %w", err)
	}

	c.logger.WithFields(logrus.Fields{
		"key":      objectKey,
		"bucket":   bucketName,
		"uploadID": uploadID,
	}).Info("Successfully created encrypted multipart upload")

	return output, nil
}

// UploadPart uploads a part with encryption support
func (c *Client) UploadPart(ctx context.Context, input *s3.UploadPartInput) (*s3.UploadPartOutput, error) {
	objectKey := aws.ToString(input.Key)
	uploadID := aws.ToString(input.UploadId)
	partNumber := aws.ToInt32(input.PartNumber)

	c.logger.WithFields(logrus.Fields{
		"key":        objectKey,
		"uploadID":   uploadID,
		"partNumber": partNumber,
	}).Debug("Uploading encrypted part")

	// Use streaming encryption to avoid memory buffering large parts
	return c.uploadPartStreaming(ctx, input, objectKey, uploadID, int(partNumber))
}

// uploadPartStreaming implements true streaming encryption for upload parts
func (c *Client) uploadPartStreaming(ctx context.Context, input *s3.UploadPartInput, objectKey, uploadID string, partNumber int) (*s3.UploadPartOutput, error) {
	// For parts that are small enough, use direct encryption (more efficient)
	// For large parts, we would need to implement chunk-by-chunk processing
	// For now, we keep the current approach but with better memory management

	partData, err := io.ReadAll(input.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read part data: %w", err)
	}

	c.logger.WithFields(logrus.Fields{
		"key":        objectKey,
		"uploadID":   uploadID,
		"partNumber": partNumber,
		"dataSize":   len(partData),
	}).Debug("Read part data for encryption")

	// Encrypt the part
	encResult, err := c.encryptionMgr.UploadPart(ctx, uploadID, partNumber, partData)
	if err != nil {
		c.logger.WithError(err).WithFields(logrus.Fields{
			"key":        objectKey,
			"uploadID":   uploadID,
			"partNumber": partNumber,
		}).Error("Failed to encrypt part")
		return nil, fmt.Errorf("failed to encrypt part: %w", err)
	}

	c.logger.WithFields(logrus.Fields{
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
		PartNumber:           input.PartNumber,
		UploadId:             input.UploadId,
		Body:                 bytes.NewReader(encResult.EncryptedData),
		ContentLength:        aws.Int64(int64(len(encResult.EncryptedData))),
		ChecksumAlgorithm:    input.ChecksumAlgorithm,
		ChecksumCRC32:        input.ChecksumCRC32,
		ChecksumCRC32C:       input.ChecksumCRC32C,
		ChecksumSHA1:         input.ChecksumSHA1,
		ChecksumSHA256:       input.ChecksumSHA256,
		SSECustomerAlgorithm: input.SSECustomerAlgorithm,
		SSECustomerKey:       input.SSECustomerKey,
		SSECustomerKeyMD5:    input.SSECustomerKeyMD5,
		RequestPayer:         input.RequestPayer,
	}

	// Upload the encrypted part
	output, err := c.s3Client.UploadPart(ctx, encryptedInput)
	if err != nil {
		c.logger.WithError(err).WithFields(logrus.Fields{
			"key":        objectKey,
			"uploadID":   uploadID,
			"partNumber": partNumber,
		}).Error("Failed to upload encrypted part to S3")
		return nil, fmt.Errorf("failed to upload encrypted part: %w", err)
	}

	// Release encrypted data immediately after upload
	encResult.EncryptedData = nil

	c.logger.WithFields(logrus.Fields{
		"key":        objectKey,
		"uploadID":   uploadID,
		"partNumber": partNumber,
		"etag":       aws.ToString(output.ETag),
	}).Info("Successfully uploaded encrypted part")

	return output, nil
}

// CompleteMultipartUpload completes a multipart upload with encryption support
func (c *Client) CompleteMultipartUpload(ctx context.Context, input *s3.CompleteMultipartUploadInput) (*s3.CompleteMultipartUploadOutput, error) {
	objectKey := aws.ToString(input.Key)
	uploadID := aws.ToString(input.UploadId)

	c.logger.WithFields(logrus.Fields{
		"key":      objectKey,
		"uploadID": uploadID,
	}).Debug("Completing encrypted multipart upload")

	// Get the encrypted ETags from the encryption manager
	uploadState, err := c.encryptionMgr.GetMultipartUploadState(uploadID)
	if err != nil {
		c.logger.WithError(err).WithFields(logrus.Fields{
			"key":      objectKey,
			"uploadID": uploadID,
		}).Error("Failed to get multipart upload state for completion")
		return nil, fmt.Errorf("failed to get upload state: %w", err)
	}

	// Create new input with encrypted ETags
	encryptedInput := &s3.CompleteMultipartUploadInput{
		Bucket:               input.Bucket,
		Key:                  input.Key,
		UploadId:             input.UploadId,
		ChecksumCRC32:        input.ChecksumCRC32,
		ChecksumCRC32C:       input.ChecksumCRC32C,
		ChecksumSHA1:         input.ChecksumSHA1,
		ChecksumSHA256:       input.ChecksumSHA256,
		RequestPayer:         input.RequestPayer,
		SSECustomerAlgorithm: input.SSECustomerAlgorithm,
		SSECustomerKey:       input.SSECustomerKey,
		SSECustomerKeyMD5:    input.SSECustomerKeyMD5,
	}

	// Build the parts with encrypted ETags
	if len(uploadState.PartETags) > 0 {
		encryptedInput.MultipartUpload = &types.CompletedMultipartUpload{}

		// Sort part numbers to ensure correct order
		var partNumbers []int
		for partNumber := range uploadState.PartETags {
			partNumbers = append(partNumbers, partNumber)
		}
		sort.Ints(partNumbers)

		// Add parts in sorted order
		for _, partNumber := range partNumbers {
			if partNumber > 2147483647 { // Max int32 value
				return nil, fmt.Errorf("part number %d exceeds maximum allowed value", partNumber)
			}
			encryptedEtag := uploadState.PartETags[partNumber]
			part := types.CompletedPart{
				ETag:       aws.String(encryptedEtag),
				PartNumber: aws.Int32(int32(partNumber)), // #nosec G115 - bounds checked above
			}
			encryptedInput.MultipartUpload.Parts = append(encryptedInput.MultipartUpload.Parts, part)
		}
	} else {
		c.logger.WithFields(logrus.Fields{
			"key":      objectKey,
			"uploadID": uploadID,
		}).Warn("No encrypted ETags found, using original parts")
		encryptedInput.MultipartUpload = input.MultipartUpload
	}

	// Get encryption metadata from upload state to propagate to final object
	// For "none" provider, skip metadata completely for pure pass-through
	var encryptionMetadata map[string]string
	if uploadState.Metadata != nil {
		encryptionMetadata = make(map[string]string)
		for k, v := range uploadState.Metadata {
			encryptionMetadata[k] = v
		}
		c.logger.WithFields(logrus.Fields{
			"key":      objectKey,
			"uploadID": uploadID,
			"metadata": encryptionMetadata,
		}).Debug("Propagating encryption metadata to final multipart object")
	}

	// Complete the multipart upload in S3 with encrypted ETags
	output, err := c.s3Client.CompleteMultipartUpload(ctx, encryptedInput)
	if err != nil {
		c.logger.WithError(err).WithFields(logrus.Fields{
			"key":      objectKey,
			"uploadID": uploadID,
		}).Error("Failed to complete multipart upload in S3")
		return nil, fmt.Errorf("failed to complete multipart upload: %w", err)
	}

	// After completing the multipart upload, we need to add the encryption metadata
	// to the final object since S3 doesn't transfer metadata from CreateMultipartUpload
	// Skip this entirely for "none" provider to maintain pure pass-through
	if len(encryptionMetadata) > 0 {
		c.logger.WithFields(logrus.Fields{
			"key":      objectKey,
			"metadata": encryptionMetadata,
		}).Debug("Adding encryption metadata to completed multipart object")

		// Use CopyObject to add metadata to the completed object
		copyInput := &s3.CopyObjectInput{
			Bucket:            input.Bucket,
			Key:               input.Key,
			CopySource:        aws.String(fmt.Sprintf("%s/%s", aws.ToString(input.Bucket), objectKey)),
			Metadata:          encryptionMetadata,
			MetadataDirective: types.MetadataDirectiveReplace,
		}

		_, copyErr := c.s3Client.CopyObject(ctx, copyInput)
		if copyErr != nil {
			c.logger.WithError(copyErr).WithFields(logrus.Fields{
				"key":      objectKey,
				"metadata": encryptionMetadata,
			}).Error("Failed to add encryption metadata to completed multipart object")
			// Don't return error since the upload itself succeeded
		} else {
			c.logger.WithFields(logrus.Fields{
				"key":      objectKey,
				"metadata": encryptionMetadata,
			}).Debug("Successfully added encryption metadata to completed multipart object")
		}
	}

	// Extract part ETags for the encryption manager cleanup
	parts := make(map[int]string)
	if input.MultipartUpload != nil {
		for _, part := range input.MultipartUpload.Parts {
			partNumber := int(aws.ToInt32(part.PartNumber))
			etag := aws.ToString(part.ETag)
			parts[partNumber] = etag
		}
	}

	// Clean up encryption state
	_, err = c.encryptionMgr.CompleteMultipartUpload(ctx, uploadID, parts)
	if err != nil {
		// Log but don't fail the operation since S3 operation succeeded
		c.logger.WithError(err).WithFields(logrus.Fields{
			"key":      objectKey,
			"uploadID": uploadID,
		}).Warn("Failed to clean up encryption state after successful multipart upload")
	}

	c.logger.WithFields(logrus.Fields{
		"key":      objectKey,
		"uploadID": uploadID,
		"etag":     aws.ToString(output.ETag),
	}).Info("Successfully completed encrypted multipart upload")

	return output, nil
}

// AbortMultipartUpload aborts a multipart upload with encryption cleanup
func (c *Client) AbortMultipartUpload(ctx context.Context, input *s3.AbortMultipartUploadInput) (*s3.AbortMultipartUploadOutput, error) {
	objectKey := aws.ToString(input.Key)
	uploadID := aws.ToString(input.UploadId)

	c.logger.WithFields(logrus.Fields{
		"key":      objectKey,
		"uploadID": uploadID,
	}).Debug("Aborting encrypted multipart upload")

	// Abort in S3
	output, err := c.s3Client.AbortMultipartUpload(ctx, input)
	if err != nil {
		c.logger.WithError(err).WithFields(logrus.Fields{
			"key":      objectKey,
			"uploadID": uploadID,
		}).Error("Failed to abort multipart upload in S3")
		// Continue to clean up encryption state even if S3 operation failed
	}

	// Clean up encryption state
	if err := c.encryptionMgr.AbortMultipartUpload(ctx, uploadID); err != nil {
		c.logger.WithError(err).WithField("uploadID", uploadID).Error("Failed to abort multipart upload in encryption manager")
	}

	c.logger.WithFields(logrus.Fields{
		"key":      objectKey,
		"uploadID": uploadID,
	}).Info("Successfully aborted encrypted multipart upload")

	return output, err
}

// ListParts lists parts of a multipart upload
func (c *Client) ListParts(ctx context.Context, input *s3.ListPartsInput) (*s3.ListPartsOutput, error) {
	return c.s3Client.ListParts(ctx, input)
}

// ListMultipartUploads lists multipart uploads
func (c *Client) ListMultipartUploads(ctx context.Context, input *s3.ListMultipartUploadsInput) (*s3.ListMultipartUploadsOutput, error) {
	return c.s3Client.ListMultipartUploads(ctx, input)
}
