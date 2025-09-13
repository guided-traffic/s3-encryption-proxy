package object

import (
	"bytes"
	"io"
	"net/http"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// handleGetObject handles GET object requests
func (h *Handler) handleGetObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	h.logger.WithFields(map[string]interface{}{
		"bucket": bucket,
		"key":    key,
	}).Debug("Getting object")

	input := &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}

	// Add range header if present
	if rangeHeader := r.Header.Get("Range"); rangeHeader != "" {
		input.Range = aws.String(rangeHeader)
	}

	// Add if-match headers
	if ifMatch := r.Header.Get("If-Match"); ifMatch != "" {
		input.IfMatch = aws.String(ifMatch)
	}
	if ifNoneMatch := r.Header.Get("If-None-Match"); ifNoneMatch != "" {
		input.IfNoneMatch = aws.String(ifNoneMatch)
	}

	output, err := h.s3Client.GetObject(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}
	defer output.Body.Close()

	// Set response headers
	if output.ContentType != nil {
		w.Header().Set("Content-Type", *output.ContentType)
	}
	if output.ContentLength != nil {
		w.Header().Set("Content-Length", strconv.FormatInt(*output.ContentLength, 10))
	}
	if output.ETag != nil {
		w.Header().Set("ETag", *output.ETag)
	}
	if output.LastModified != nil {
		w.Header().Set("Last-Modified", output.LastModified.Format("Mon, 02 Jan 2006 15:04:05 GMT"))
	}

	// Copy metadata headers (but filter out encryption metadata)
	if output.Metadata != nil {
		for key, value := range output.Metadata {
			if !h.isEncryptionMetadata(key) {
				w.Header().Set("x-amz-meta-"+key, value)
			}
		}
	}

	w.WriteHeader(http.StatusOK)

	// Stream the object body
	if _, err := io.Copy(w, output.Body); err != nil {
		h.logger.WithError(err).Error("Failed to write object data")
	}
}

// handlePutObject handles PUT object requests
func (h *Handler) handlePutObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	h.logger.WithFields(map[string]interface{}{
		"bucket": bucket,
		"key":    key,
	}).Debug("Putting object")

	// Read the request body
	body, err := h.requestParser.ReadBody(r)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}

	input := &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(body),
	}

	// Set content type if provided
	if contentType := r.Header.Get("Content-Type"); contentType != "" {
		input.ContentType = aws.String(contentType)
	}

	// Add metadata from headers
	metadata := make(map[string]string)
	for headerName, headerValues := range r.Header {
		if len(headerValues) > 0 && len(headerName) > 11 && headerName[:11] == "x-amz-meta-" {
			metaKey := headerName[11:] // Remove "x-amz-meta-" prefix
			metadata[metaKey] = headerValues[0]
		}
	}
	if len(metadata) > 0 {
		input.Metadata = metadata
	}

	output, err := h.s3Client.PutObject(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}

	// Set response headers
	if output.ETag != nil {
		w.Header().Set("ETag", *output.ETag)
	}

	w.WriteHeader(http.StatusOK)
}

// handleDeleteObject handles DELETE object requests
func (h *Handler) handleDeleteObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	h.logger.WithFields(map[string]interface{}{
		"bucket": bucket,
		"key":    key,
	}).Debug("Deleting object")

	input := &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}

	_, err := h.s3Client.DeleteObject(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleHeadObject handles HEAD object requests
func (h *Handler) handleHeadObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	h.logger.WithFields(map[string]interface{}{
		"bucket": bucket,
		"key":    key,
	}).Debug("Getting object metadata")

	input := &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}

	output, err := h.s3Client.HeadObject(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}

	// Set response headers
	if output.ContentType != nil {
		w.Header().Set("Content-Type", *output.ContentType)
	}
	if output.ContentLength != nil {
		w.Header().Set("Content-Length", strconv.FormatInt(*output.ContentLength, 10))
	}
	if output.ETag != nil {
		w.Header().Set("ETag", *output.ETag)
	}
	if output.LastModified != nil {
		w.Header().Set("Last-Modified", output.LastModified.Format("Mon, 02 Jan 2006 15:04:05 GMT"))
	}

	// Copy metadata headers (but filter out encryption metadata)
	if output.Metadata != nil {
		for key, value := range output.Metadata {
			if !h.isEncryptionMetadata(key) {
				w.Header().Set("x-amz-meta-"+key, value)
			}
		}
	}

	w.WriteHeader(http.StatusOK)
}

// isEncryptionMetadata checks if a metadata key is encryption-related
func (h *Handler) isEncryptionMetadata(key string) bool {
	prefix := h.requestParser.GetMetadataPrefix()
	if prefix == "" {
		prefix = "s3ep-"
	}
	return len(key) >= len(prefix) && key[:len(prefix)] == prefix
}
