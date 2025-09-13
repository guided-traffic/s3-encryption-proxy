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
	s3Client        interfaces.S3ClientInterface
	encryptionMgr   *encryption.Manager
	logger          *logrus.Entry
	xmlWriter       *response.XMLWriter
	errorWriter     *response.ErrorWriter
	requestParser   *request.Parser
}

// NewCompleteHandler creates a new complete handler
func NewCompleteHandler(
	s3Client interfaces.S3ClientInterface,
	encryptionMgr *encryption.Manager,
	logger *logrus.Entry,
	xmlWriter *response.XMLWriter,
	errorWriter *response.ErrorWriter,
	requestParser *request.Parser,
) *CompleteHandler {
	return &CompleteHandler{
		s3Client:      s3Client,
		encryptionMgr: encryptionMgr,
		logger:        logger,
		xmlWriter:     xmlWriter,
		errorWriter:   errorWriter,
		requestParser: requestParser,
	}
}

// CompleteMultipartUpload represents the XML payload for completing a multipart upload
type CompleteMultipartUpload struct {
	XMLName xml.Name               `xml:"CompleteMultipartUpload"`
	Parts   []CompletedPart        `xml:"Part"`
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
		"uploadId": uploadID,
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
	log.WithField("decoded_body", decodedBody).Debug("Decoded request body")

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

	log.WithField("parts", completeUpload.Parts).Debug("Parts validated and sorted")

	// Convert to S3 types
	var completedParts []types.CompletedPart
	for _, part := range completeUpload.Parts {
		// Clean ETag (remove quotes if present)
		cleanETag := strings.Trim(part.ETag, "\"")
		completedParts = append(completedParts, types.CompletedPart{
			PartNumber: aws.Int32(int32(part.PartNumber)),
			ETag:       aws.String(cleanETag),
		})
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

	ctx := r.Context()
	result, err := h.s3Client.CompleteMultipartUpload(ctx, completeInput)
	if err != nil {
		log.WithError(err).Error("Failed to complete multipart upload")
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}

	// Clean up upload state in encryption manager
	if h.encryptionMgr != nil {
		if err := h.encryptionMgr.CleanupMultipartUpload(uploadID); err != nil {
			log.WithError(err).Warn("Failed to cleanup multipart upload state")
			// Continue - this is not a critical error
		}
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
		result.Location,
		bucket,
		key,
		*result.ETag)

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(responseXML))

	log.WithFields(logrus.Fields{
		"etag":       result.ETag,
		"location":   result.Location,
		"parts_count": len(completedParts),
	}).Info("Successfully completed multipart upload")
}
