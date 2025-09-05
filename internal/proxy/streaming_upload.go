package proxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gorilla/mux"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/providers"
)

// StreamingUploadPart represents a streaming upload part operation
type StreamingUploadPart struct {
	server      *Server
	uploadID    string
	partNumber  int
	bucket      string
	key         string
	encProvider *providers.AESCTRProvider
	dek         []byte
	iv          []byte
	counter     uint64
}

// handleStreamingUploadPart handles upload part with streaming encryption
func (s *Server) handleStreamingUploadPart(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]

	// Parse query parameters
	uploadID := r.URL.Query().Get("uploadId")
	partNumberStr := r.URL.Query().Get("partNumber")

	if uploadID == "" || partNumberStr == "" {
		http.Error(w, "Missing uploadId or partNumber", http.StatusBadRequest)
		return
	}

	partNumber, err := strconv.Atoi(partNumberStr)
	if err != nil || partNumber < 1 || partNumber > 10000 {
		http.Error(w, "Invalid partNumber", http.StatusBadRequest)
		return
	}

	s.logger.WithFields(map[string]interface{}{
		"bucket":     bucket,
		"key":        key,
		"uploadId":   uploadID,
		"partNumber": partNumber,
	}).Debug("Starting streaming upload part")

	// Get upload state
	uploadState, err := s.encryptionMgr.GetMultipartUploadState(uploadID)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get multipart upload state")
		http.Error(w, "Invalid upload ID", http.StatusBadRequest)
		return
	}

	s.logger.WithFields(map[string]interface{}{
		"uploadId":       uploadID,
		"providerAlias":  uploadState.ProviderAlias,
		"encryptionMode": uploadState.Metadata["encryption-mode"],
		"totalBytes":     uploadState.TotalBytes,
		"metadata":       uploadState.Metadata,
	}).Debug("DEBUG: Upload state retrieved")

	// Check if this is a streaming upload
	if uploadState.Metadata["encryption-mode"] != "aes-ctr-streaming" {
		s.logger.WithFields(map[string]interface{}{
			"expected": "aes-ctr-streaming",
			"actual":   uploadState.Metadata["encryption-mode"],
		}).Debug("DEBUG: Falling back to standard upload handler")
		// Fall back to standard upload part handling
		s.handleUploadPart(w, r)
		return
	}

	s.logger.Debug("DEBUG: Using streaming upload handler")

	// Get the AES-CTR provider
	provider, exists := s.encryptionMgr.GetProvider(uploadState.ProviderAlias)
	if !exists {
		s.logger.Error("Provider not found for streaming upload")
		http.Error(w, "Encryption provider not available", http.StatusInternalServerError)
		return
	}

	aesCTRProvider, ok := provider.(*providers.AESCTRProvider)
	if !ok {
		s.logger.Error("Provider is not AES-CTR for streaming upload")
		http.Error(w, "Invalid encryption provider", http.StatusInternalServerError)
		return
	}

	// Create streaming upload part
	streamingPart := &StreamingUploadPart{
		server:      s,
		uploadID:    uploadID,
		partNumber:  partNumber,
		bucket:      bucket,
		key:         key,
		encProvider: aesCTRProvider,
		dek:         uploadState.DEK,
		iv:          uploadState.Counter,
		counter:     uint64(uploadState.TotalBytes), // Counter is byte-based
	}

	// Start streaming upload
	if err := streamingPart.Start(r.Context(), r.Body, w); err != nil {
		s.logger.WithError(err).Error("Failed to stream upload part")
		http.Error(w, "Failed to upload part", http.StatusInternalServerError)
		return
	}
}

// Start initiates the streaming upload process
func (sp *StreamingUploadPart) Start(ctx context.Context, reader io.Reader, w http.ResponseWriter) error {
	// Instead of streaming with pipe, buffer the encrypted data first
	var encryptedBuffer bytes.Buffer

	// Read and encrypt all data into buffer
	if err := sp.encryptToBuffer(ctx, reader, &encryptedBuffer); err != nil {
		return err
	}

	// Upload the buffered encrypted data to S3
	return sp.uploadBufferToS3(ctx, &encryptedBuffer, w)
}

// encryptToBuffer encrypts data and writes it to a buffer
func (sp *StreamingUploadPart) encryptToBuffer(ctx context.Context, reader io.Reader, buffer *bytes.Buffer) error {
	bufferData := make([]byte, 64*1024) // 64KB buffer
	totalBytes := int64(0)

	for {
		n, err := reader.Read(bufferData)
		if n > 0 {
			chunk := bufferData[:n]

			// Encrypt chunk with current counter
			encryptedChunk, encErr := sp.encProvider.EncryptStream(ctx, chunk, sp.dek, sp.iv, sp.counter)
			if encErr != nil {
				sp.server.logger.WithError(encErr).Error("Failed to encrypt chunk")
				return encErr
			}

			// Write encrypted chunk to buffer
			if _, writeErr := buffer.Write(encryptedChunk); writeErr != nil {
				sp.server.logger.WithError(writeErr).Error("Failed to write encrypted chunk to buffer")
				return writeErr
			}

			// Update counter for next chunk
			totalBytes += int64(n)
			sp.counter += uint64(n) // Update counter by bytes processed
		}

		if err == io.EOF {
			break
		}
		if err != nil {
			sp.server.logger.WithError(err).Error("Failed to read chunk")
			return err
		}
	}

	// Update total bytes in upload state
	if err := sp.server.encryptionMgr.UpdateMultipartTotalBytes(sp.uploadID, totalBytes); err != nil {
		sp.server.logger.WithError(err).Error("Failed to update total bytes")
	}

	return nil
}

// uploadBufferToS3 uploads the encrypted buffer to S3
func (sp *StreamingUploadPart) uploadBufferToS3(ctx context.Context, buffer *bytes.Buffer, w http.ResponseWriter) error {
	// Upload part to S3 with known content length
	input := &s3.UploadPartInput{
		Bucket:        aws.String(sp.bucket),
		Key:           aws.String(sp.key),
		PartNumber:    aws.Int32(int32(sp.partNumber)),
		UploadId:      aws.String(sp.uploadID),
		Body:          bytes.NewReader(buffer.Bytes()),
		ContentLength: aws.Int64(int64(buffer.Len())), // Now we know the length!
	}

	result, err := sp.server.s3Client.UploadPart(ctx, input)
	if err != nil {
		sp.server.logger.WithError(err).Error("Failed to upload part to S3")
		return err
	}

	// Record the ETag
	if err := sp.server.encryptionMgr.RecordPartETag(sp.uploadID, sp.partNumber, aws.ToString(result.ETag)); err != nil {
		sp.server.logger.WithError(err).Error("Failed to record part ETag")
		return err
	}

	// Send response to client
	w.Header().Set("ETag", aws.ToString(result.ETag))
	w.WriteHeader(http.StatusOK)

	return nil
}
