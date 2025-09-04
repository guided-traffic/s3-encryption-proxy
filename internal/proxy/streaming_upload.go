package proxy

import (
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
	server         *Server
	uploadID       string
	partNumber     int
	bucket         string
	key            string
	encProvider    *providers.AESCTRProvider
	dek            []byte
	iv             []byte
	counter        uint64
	s3UploadReader *io.PipeReader
	s3UploadWriter *io.PipeWriter
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

	// Check if this is a streaming upload
	if uploadState.Metadata["encryption-mode"] != "aes-ctr-streaming" {
		// Fall back to standard upload part handling
		s.handleUploadPart(w, r)
		return
	}

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
		counter:     uint64(uploadState.TotalBytes / 16), // AES block size
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
	// Create pipe for streaming encrypted data to S3
	sp.s3UploadReader, sp.s3UploadWriter = io.Pipe()

	// Channel for errors
	errCh := make(chan error, 2)

	// Start S3 upload in a goroutine
	go sp.uploadToS3(ctx, errCh, w)

	// Start encryption and streaming in another goroutine
	go sp.encryptAndStream(ctx, reader, errCh)

	// Wait for completion or error
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			// Close the pipe to clean up
			sp.s3UploadWriter.Close()
			return err
		}
	}

	return nil
}

// uploadToS3 uploads the encrypted data stream to S3
func (sp *StreamingUploadPart) uploadToS3(ctx context.Context, errCh chan<- error, w http.ResponseWriter) {
	defer func() {
		sp.s3UploadReader.Close()
	}()

	// Upload part to S3
	input := &s3.UploadPartInput{
		Bucket:     aws.String(sp.bucket),
		Key:        aws.String(sp.key),
		PartNumber: aws.Int32(int32(sp.partNumber)),
		UploadId:   aws.String(sp.uploadID),
		Body:       sp.s3UploadReader,
	}

	result, err := sp.server.s3Client.UploadPart(ctx, input)
	if err != nil {
		sp.server.logger.WithError(err).Error("Failed to upload part to S3")
		errCh <- err
		return
	}

	// Record the ETag
	if err := sp.server.encryptionMgr.RecordPartETag(sp.uploadID, sp.partNumber, aws.ToString(result.ETag)); err != nil {
		sp.server.logger.WithError(err).Error("Failed to record part ETag")
		errCh <- err
		return
	}

	// Send response to client
	w.Header().Set("ETag", aws.ToString(result.ETag))
	w.WriteHeader(http.StatusOK)

	errCh <- nil
}

// encryptAndStream encrypts data and streams it to S3
func (sp *StreamingUploadPart) encryptAndStream(ctx context.Context, reader io.Reader, errCh chan<- error) {
	defer sp.s3UploadWriter.Close()

	buffer := make([]byte, 64*1024) // 64KB buffer
	totalBytes := int64(0)

	for {
		n, err := reader.Read(buffer)
		if n > 0 {
			chunk := buffer[:n]

			// Encrypt chunk with current counter
			encryptedChunk, encErr := sp.encProvider.EncryptStream(ctx, chunk, sp.dek, sp.iv, sp.counter)
			if encErr != nil {
				sp.server.logger.WithError(encErr).Error("Failed to encrypt chunk")
				errCh <- encErr
				return
			}

			// Write encrypted chunk to S3 stream
			if _, writeErr := sp.s3UploadWriter.Write(encryptedChunk); writeErr != nil {
				sp.server.logger.WithError(writeErr).Error("Failed to write encrypted chunk")
				errCh <- writeErr
				return
			}

			// Update counter for next chunk
			totalBytes += int64(n)
			sp.counter += uint64(n) / 16 // Update counter based on blocks processed
		}

		if err == io.EOF {
			break
		}
		if err != nil {
			sp.server.logger.WithError(err).Error("Failed to read chunk")
			errCh <- err
			return
		}
	}

	// Update total bytes in upload state
	if err := sp.server.encryptionMgr.UpdateMultipartTotalBytes(sp.uploadID, totalBytes); err != nil {
		sp.server.logger.WithError(err).Error("Failed to update total bytes")
	}

	errCh <- nil
}
