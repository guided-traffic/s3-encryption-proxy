package request

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

// AWSChunkedReader reads data from AWS Signature V4 chunked encoded streams.
// This handles the special chunked format used by AWS which includes chunk signatures.
//
// Format:
// {hex_chunk_size};chunk-signature={signature}\r\n
// {chunk_data}\r\n
// ...
// 0;chunk-signature=final-signature\r\n\r\n
type AWSChunkedReader struct {
	reader    *bufio.Reader
	chunkLeft int64 // bytes left in current chunk
	finished  bool
	err       error
}

// NewAWSChunkedReader creates a new AWS chunked reader
func NewAWSChunkedReader(r io.Reader) *AWSChunkedReader {
	return &AWSChunkedReader{
		reader:    bufio.NewReader(r),
		chunkLeft: 0,
		finished:  false,
	}
}

// Read implements io.Reader
func (r *AWSChunkedReader) Read(p []byte) (n int, err error) {
	if r.finished {
		return 0, io.EOF
	}

	if r.err != nil {
		return 0, r.err
	}

	// If we have no bytes left in the current chunk, read the next chunk header
	if r.chunkLeft == 0 {
		if err := r.readNextChunk(); err != nil {
			r.err = err
			if err == io.EOF {
				r.finished = true
			}
			return 0, err
		}
	}

	// If we're finished (got a 0-length chunk), return EOF
	if r.finished {
		return 0, io.EOF
	}

	// Read data from the current chunk
	readBytes := int64(len(p))
	if readBytes > r.chunkLeft {
		readBytes = r.chunkLeft
	}

	n, err = r.reader.Read(p[:readBytes])
	r.chunkLeft -= int64(n)

	// If we've finished this chunk, consume the trailing CRLF
	if r.chunkLeft == 0 {
		trailingErr := r.consumeTrailingCRLF()
		if trailingErr != nil {
			r.err = trailingErr
			return n, trailingErr
		}
	}

	// Handle the original read error (but don't propagate EOF if we successfully read the chunk)
	if err != nil && r.chunkLeft > 0 {
		r.err = err
	}

	return n, err
}

// readNextChunk reads the next chunk header and sets up for chunk data reading
func (r *AWSChunkedReader) readNextChunk() error {
	// Read chunk size line (format: "hex_size;chunk-signature=signature\r\n")
	chunkSizeLine, err := r.reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read chunk size line: %w", err)
	}

	chunkSizeLine = strings.TrimSpace(chunkSizeLine)

	if chunkSizeLine == "" {
		return fmt.Errorf("empty chunk size line")
	}

	// Parse chunk size (everything before the semicolon)
	parts := strings.Split(chunkSizeLine, ";")
	if len(parts) == 0 {
		return fmt.Errorf("invalid AWS chunk header format: %q", chunkSizeLine)
	}

	chunkSizeStr := parts[0]
	if chunkSizeStr == "" {
		return fmt.Errorf("empty chunk size in header: %q", chunkSizeLine)
	}

	chunkSize, err := strconv.ParseInt(chunkSizeStr, 16, 64)
	if err != nil {
		return fmt.Errorf("invalid AWS chunk size %q in header %q: %w", chunkSizeStr, chunkSizeLine, err)
	}

	// If chunk size is 0, this is the final chunk
	if chunkSize == 0 {
		r.finished = true
		// Consume final CRLF after the 0-size chunk header
		// We need to consume the remaining \r\n (just two bytes)
		finalCRLF := make([]byte, 2)
		if _, err := io.ReadFull(r.reader, finalCRLF); err != nil && err != io.EOF {
			return fmt.Errorf("failed to consume final CRLF: %w", err)
		}
		return io.EOF
	}

	r.chunkLeft = chunkSize
	return nil
}

// consumeTrailingCRLF reads the trailing \r\n after chunk data
func (r *AWSChunkedReader) consumeTrailingCRLF() error {
	// Read the trailing \r\n after chunk data
	_, err := r.reader.ReadString('\n')
	return err
}

// ReadAll is a convenience method to read all data from the AWS chunked stream
func ReadAllAWSChunked(r io.Reader) ([]byte, error) {
	chunkedReader := NewAWSChunkedReader(r)
	return io.ReadAll(chunkedReader)
}

// ChunkedEncodingDetector handles all chunked encoding detection and processing
type ChunkedEncodingDetector struct {
	logger *logrus.Entry
}

// NewChunkedEncodingDetector creates a new chunked encoding detector
func NewChunkedEncodingDetector(logger *logrus.Entry) *ChunkedEncodingDetector {
	return &ChunkedEncodingDetector{
		logger: logger,
	}
}

// RequiresChunkedDecoding analyzes request metadata to determine if chunked decoding is needed
func (d *ChunkedEncodingDetector) RequiresChunkedDecoding(r *http.Request) bool {
	// Check Transfer-Encoding header for standard chunked encoding
	if len(r.TransferEncoding) > 0 && r.TransferEncoding[0] == "chunked" {
		d.logger.Debug("Detected standard chunked transfer encoding")
		return true
	}

	// Check for AWS Signature V4 streaming (definitive detection)
	if r.Header.Get("X-Amz-Content-Sha256") == "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" {
		d.logger.Debug("Detected AWS Signature V4 streaming via X-Amz-Content-Sha256 header")
		return true
	}

	// Check for additional chunked encoding indicators
	contentEncoding := r.Header.Get("Content-Encoding")
	if strings.Contains(contentEncoding, "aws-chunked") {
		d.logger.Debug("Detected aws-chunked in Content-Encoding header")
		return true
	}

	return false
}

// AnalyzeFirstLine examines the first line of upload data to detect chunks
func (d *ChunkedEncodingDetector) AnalyzeFirstLine(data []byte) (bool, error) {
	if len(data) == 0 {
		return false, nil
	}

	// Look for the first line (up to first \n)
	firstLineEnd := 0
	for i, b := range data {
		if b == '\n' {
			firstLineEnd = i
			break
		}
		// Prevent scanning too far for chunk headers
		if i > 100 {
			break
		}
	}

	if firstLineEnd == 0 {
		// No newline found in reasonable range
		return false, nil
	}

	firstLine := strings.TrimSpace(string(data[:firstLineEnd]))

	// AWS chunked format: {hex_chunk_size};chunk-signature={signature}
	if strings.Contains(firstLine, ";chunk-signature=") {
		d.logger.WithField("firstLine", firstLine).Debug("Detected AWS chunked format in first line")
		return true, nil
	}

	// Standard HTTP chunked format: {hex_chunk_size}
	// Try to parse as hex number to validate
	parts := strings.Split(firstLine, ";")
	if len(parts) > 0 {
		if _, err := strconv.ParseInt(parts[0], 16, 64); err == nil {
			d.logger.WithField("firstLine", firstLine).Debug("Detected potential chunked format in first line")
			return true, nil
		}
	}

	return false, nil
}

// ProcessChunkedData validates chunks and extracts raw data from entire upload
func (d *ChunkedEncodingDetector) ProcessChunkedData(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}

	// Use the existing AWS chunked reader for processing
	reader := NewAWSChunkedReader(strings.NewReader(string(data)))

	// Extract all raw data
	rawData, err := io.ReadAll(reader)
	if err != nil {
		d.logger.WithError(err).Debug("Failed to process as AWS chunked data, trying fallback")

		// Fallback: try to process as standard HTTP chunked encoding
		return d.processStandardChunked(data)
	}

	d.logger.WithFields(logrus.Fields{
		"originalSize": len(data),
		"extractedSize": len(rawData),
	}).Debug("Successfully processed AWS chunked data")

	return rawData, nil
}

// processStandardChunked handles standard HTTP chunked encoding as fallback
func (d *ChunkedEncodingDetector) processStandardChunked(data []byte) ([]byte, error) {
	// For standard HTTP chunked encoding, we need to implement basic chunk parsing
	// This is a simplified implementation for common cases

	reader := bufio.NewReader(strings.NewReader(string(data)))
	var result []byte

	for {
		// Read chunk size line
		chunkSizeLine, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF && len(result) > 0 {
				break // Successfully processed some data
			}
			// If no data was processed, return original data
			d.logger.WithError(err).Debug("Failed to parse as chunked data, returning original")
			return data, nil
		}

		chunkSizeLine = strings.TrimSpace(chunkSizeLine)
		if chunkSizeLine == "" {
			continue
		}

		// Parse chunk size (hex)
		chunkSize, err := strconv.ParseInt(chunkSizeLine, 16, 64)
		if err != nil {
			// Not valid chunked format, return original data
			d.logger.WithError(err).Debug("Invalid chunk size, returning original data")
			return data, nil
		}

		// If chunk size is 0, we're done
		if chunkSize == 0 {
			break
		}

		// Read chunk data
		chunkData := make([]byte, chunkSize)
		n, err := io.ReadFull(reader, chunkData)
		if err != nil {
			d.logger.WithError(err).Debug("Failed to read chunk data, returning partial result")
			if len(result) > 0 {
				return result, nil
			}
			return data, nil
		}

		result = append(result, chunkData[:n]...)

		// Consume trailing CRLF
		reader.ReadString('\n')
	}

	if len(result) == 0 {
		// No chunked data was found, return original
		return data, nil
	}

	d.logger.WithFields(logrus.Fields{
		"originalSize": len(data),
		"extractedSize": len(result),
	}).Debug("Successfully processed standard chunked data")

	return result, nil
}

// CreateOptimalReader creates the optimal reader for the request
func (d *ChunkedEncodingDetector) CreateOptimalReader(r *http.Request) io.Reader {
	if d.RequiresChunkedDecoding(r) {
		d.logger.Debug("Creating AWS chunked reader for optimal processing")
		return NewAWSChunkedReader(r.Body)
	}

	d.logger.Debug("Using standard body reader")
	return r.Body
}

// ProcessRequestBody handles complete request body processing with chunked decoding
func (d *ChunkedEncodingDetector) ProcessRequestBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}

	// Check if chunked decoding is required
	if !d.RequiresChunkedDecoding(r) {
		// Standard body reading
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
		return body, nil
	}

	// Use chunked processing
	d.logger.Debug("Processing chunked request body")

	// Read all data first
	allData, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read chunked request body: %w", err)
	}

	// Process chunked data to extract raw content
	rawData, err := d.ProcessChunkedData(allData)
	if err != nil {
		return nil, fmt.Errorf("failed to process chunked data: %w", err)
	}

	return rawData, nil
}
