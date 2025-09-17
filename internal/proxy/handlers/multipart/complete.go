package multipart

import (
	"encoding/xml"
	"fmt"
	"html"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gorilla/mux"
	"github.com/guided-traffic/s3-encryption-proxy/internal/encryption"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/interfaces"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/request"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
	"github.com/sirupsen/logrus"
)

// CompleteHandler handles complete multipart upload operations
type CompleteHandler struct {
	s3Backend     interfaces.S3BackendInterface
	encryptionMgr *encryption.Manager
	logger        *logrus.Entry
	xmlWriter     *response.XMLWriter
	errorWriter   *response.ErrorWriter
	requestParser *request.Parser
}

// NewCompleteHandler creates a new complete handler
func NewCompleteHandler(
	s3Backend interfaces.S3BackendInterface,
	encryptionMgr *encryption.Manager,
	logger *logrus.Entry,
	xmlWriter *response.XMLWriter,
	errorWriter *response.ErrorWriter,
	requestParser *request.Parser,
) *CompleteHandler {
	return &CompleteHandler{
		s3Backend:     s3Backend,
		encryptionMgr: encryptionMgr,
		logger:        logger,
		xmlWriter:     xmlWriter,
		errorWriter:   errorWriter,
		requestParser: requestParser,
	}
}

// CompleteMultipartUpload represents the XML payload for completing a multipart upload
type CompleteMultipartUpload struct {
	XMLName xml.Name        `xml:"CompleteMultipartUpload"`
	Parts   []CompletedPart `xml:"Part"`
}

// CompletedPart represents a completed part in the multipart upload
type CompletedPart struct {
	PartNumber int    `xml:"PartNumber"`
	ETag       string `xml:"ETag"`
}

// Handle handles complete multipart upload requests
func (h *CompleteHandler) Handle(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]

	// Parse query parameters
	uploadID := r.URL.Query().Get("uploadId")

	log := h.logger.WithFields(logrus.Fields{
		"bucket":   bucket,
		"key":      key,
		"uploadID": uploadID,
		"method":   r.Method,
	})

	log.Debug("CompleteMultipartUpload - Request received")

	if uploadID == "" {
		log.Error("Missing uploadId")
		h.errorWriter.WriteS3Error(w, fmt.Errorf("missing uploadId"), bucket, key)
		return
	}

	// Read and decode the request body
	bodyData, err := io.ReadAll(r.Body)
	if err != nil {
		log.WithError(err).Error("Failed to read request body")
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}

	log.WithField("body_size", len(bodyData)).Debug("Read request body")

	// Decode HTML entities (AWS clients sometimes send encoded XML)
	decodedBody := html.UnescapeString(string(bodyData))
	// log.WithField("decoded_body", decodedBody).Debug("Decoded request body")

	// Parse the XML
	var completeUpload CompleteMultipartUpload
	if err := xml.Unmarshal([]byte(decodedBody), &completeUpload); err != nil {
		log.WithError(err).WithField("body", decodedBody).Error("Failed to parse XML body")
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}

	log.WithField("parts_count", len(completeUpload.Parts)).Debug("Parsed XML successfully")

	// Validate and sort parts
	if len(completeUpload.Parts) == 0 {
		log.Error("No parts provided")
		h.errorWriter.WriteS3Error(w, fmt.Errorf("no parts provided"), bucket, key)
		return
	}

	// Sort parts by part number
	sort.Slice(completeUpload.Parts, func(i, j int) bool {
		return completeUpload.Parts[i].PartNumber < completeUpload.Parts[j].PartNumber
	})

	// Validate part sequence
	for i, part := range completeUpload.Parts {
		if part.PartNumber < 1 || part.PartNumber > 10000 {
			log.WithField("part_number", part.PartNumber).Error("Invalid part number")
			h.errorWriter.WriteS3Error(w, fmt.Errorf("invalid part number: %d", part.PartNumber), bucket, key)
			return
		}
		if part.ETag == "" {
			log.WithField("part_number", part.PartNumber).Error("Missing ETag")
			h.errorWriter.WriteS3Error(w, fmt.Errorf("missing ETag for part %d", part.PartNumber), bucket, key)
			return
		}
		// Check for duplicate part numbers
		if i > 0 && completeUpload.Parts[i-1].PartNumber == part.PartNumber {
			log.WithField("part_number", part.PartNumber).Error("Duplicate part number")
			h.errorWriter.WriteS3Error(w, fmt.Errorf("duplicate part number: %d", part.PartNumber), bucket, key)
			return
		}
	}

	// log.WithField("parts", completeUpload.Parts).Debug("Parts validated and sorted")

	ctx := r.Context()

	// Build completion map from input parts for encryption manager
	parts := make(map[int]string)
	var completedParts []types.CompletedPart
	for _, part := range completeUpload.Parts {
		// Validate part number is within int32 range
		if part.PartNumber < 1 || part.PartNumber > 10000 {
			h.logger.WithFields(logrus.Fields{
				"bucket":     bucket,
				"key":        key,
				"uploadID":   uploadID,
				"partNumber": part.PartNumber,
			}).Error("Part number out of valid range in complete request")
			h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "InvalidPartNumber", "Part number must be between 1 and 10000")
			return
		}

		cleanETag := strings.Trim(part.ETag, "\"")
		parts[part.PartNumber] = cleanETag
		completedParts = append(completedParts, types.CompletedPart{
			PartNumber: aws.Int32(int32(part.PartNumber)),
			ETag:       aws.String(cleanETag),
		})
	}

	// Complete the multipart upload with encryption
	finalMetadata, err := h.encryptionMgr.CompleteMultipartUpload(ctx, uploadID, parts)
	if err != nil {
		log.WithError(err).Error("Failed to complete multipart upload with encryption")
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}

	// Debug: Log the finalMetadata content in a single entry
	if len(finalMetadata) > 0 {
		log.WithFields(logrus.Fields{
			"uploadID":      uploadID,
			"metadataCount": len(finalMetadata),
			"metadata":      finalMetadata,
		}).Debug("Final metadata entries")
	} else {
		log.WithFields(logrus.Fields{
			"uploadID": uploadID,
		}).Debug("No final metadata received from encryption manager")
	}

	// Complete the multipart upload
	completeInput := &s3.CompleteMultipartUploadInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(key),
		UploadId: aws.String(uploadID),
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: completedParts,
		},
	}

	result, err := h.s3Backend.CompleteMultipartUpload(ctx, completeInput)
	if err != nil {
		log.WithError(err).Error("Failed to complete multipart upload")
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}

	// Store the original ETag before any metadata operations
	originalETag := aws.ToString(result.ETag)

	// After completing the multipart upload, we need to add the encryption metadata
	// to the final object since S3 doesn't transfer metadata from CreateMultipartUpload
	// Skip this entirely for "none" provider to maintain pure pass-through
	if len(finalMetadata) > 0 {
		log.WithFields(logrus.Fields{
			"uploadID":      uploadID,
			"metadataCount": len(finalMetadata),
		}).Debug("Adding encryption metadata to completed object")

		// Copy the object to itself with the encryption metadata
		copyInput := &s3.CopyObjectInput{
			Bucket:            aws.String(bucket),
			Key:               aws.String(key),
			CopySource:        aws.String(fmt.Sprintf("%s/%s", bucket, key)),
			Metadata:          finalMetadata,
			MetadataDirective: types.MetadataDirectiveReplace,
		}

		copyResult, err := h.s3Backend.CopyObject(ctx, copyInput)
		if err != nil {
			log.WithFields(logrus.Fields{
				"uploadID": uploadID,
			}).WithError(err).Error("Failed to add encryption metadata to completed object")

			// CRITICAL: Without metadata, the encrypted object is unusable!
			// Return error to client to indicate the upload failed completely
			h.errorWriter.WriteS3Error(w, fmt.Errorf("upload completed but encryption metadata could not be applied: %w", err), bucket, key)
			return
		} else {
			_ = copyResult // Silence unused variable warning
			log.WithFields(logrus.Fields{
				"uploadID": uploadID,
			}).Debug("Successfully added encryption metadata to completed object")
		}
	} else {
		log.WithFields(logrus.Fields{
			"uploadID": uploadID,
		}).Debug("No metadata to add to completed object")
	}

	// Clean up upload state in encryption manager
	if h.encryptionMgr != nil {
		if err := h.encryptionMgr.CleanupMultipartUpload(uploadID); err != nil {
			log.WithError(err).Warn("Failed to cleanup multipart upload state")
			// Continue - this is not a critical error
		}
	}

	// Restore the original ETag if it was lost during metadata operations
	if originalETag != "" && aws.ToString(result.ETag) == "" {
		result.ETag = aws.String(originalETag)
	}

	// Set response headers
	if result.ETag != nil {
		w.Header().Set("ETag", *result.ETag)
	}
	if result.ServerSideEncryption != "" {
		w.Header().Set("x-amz-server-side-encryption", string(result.ServerSideEncryption))
	}
	if result.SSEKMSKeyId != nil {
		w.Header().Set("x-amz-server-side-encryption-aws-kms-key-id", *result.SSEKMSKeyId)
	}

	// Build response XML
	responseXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<CompleteMultipartUploadResult>
    <Location>%s</Location>
    <Bucket>%s</Bucket>
    <Key>%s</Key>
    <ETag>%s</ETag>
</CompleteMultipartUploadResult>`,
		aws.ToString(result.Location),
		bucket,
		key,
		aws.ToString(result.ETag))

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(responseXML)); err != nil {
		h.logger.WithError(err).Error("Failed to write complete multipart upload response")
	}

	log.WithFields(logrus.Fields{
		"etag":        result.ETag,
		"location":    result.Location,
		"parts_count": len(completedParts),
	}).Debug("Successfully completed multipart upload")
}
