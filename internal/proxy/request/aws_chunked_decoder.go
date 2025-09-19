package request

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

// AWSChunkedDecoder handles AWS Signature V4 chunked encoding
type AWSChunkedDecoder struct {
	*ChunkedDecoderBase
}

// NewAWSChunkedDecoder creates a new AWS chunked decoder
func NewAWSChunkedDecoder(logger *logrus.Entry) *AWSChunkedDecoder {
	return &AWSChunkedDecoder{
		ChunkedDecoderBase: NewChunkedDecoderBase(logger),
	}
}

// RequiresChunkedDecoding checks if this is AWS Signature V4 chunked data
func (d *AWSChunkedDecoder) RequiresChunkedDecoding(r *http.Request) bool {
	// Check for AWS chunk signature in request body
	if r.Body == nil {
		return false
	}

	// Read a small sample to check format
	buf := make([]byte, 1024)
	n, err := r.Body.Read(buf)
	if err != nil && err != io.EOF {
		return false
	}

	// Reset body
	if seeker, ok := r.Body.(io.Seeker); ok {
		seeker.Seek(0, io.SeekStart)
	} else {
		// Create new reader with full data
		fullData := make([]byte, n)
		copy(fullData, buf[:n])
		remaining, _ := io.ReadAll(r.Body)
		fullData = append(fullData, remaining...)
		r.Body = io.NopCloser(bytes.NewReader(fullData))
	}

	// Check for AWS chunk signature pattern
	sample := string(buf[:n])
	return strings.Contains(sample, ";chunk-signature=")
}

// ProcessChunkedData processes AWS chunked data and extracts content
func (d *AWSChunkedDecoder) ProcessChunkedData(data []byte) ([]byte, error) {
	reader := bytes.NewReader(data)
	scanner := bufio.NewScanner(reader)
	var result bytes.Buffer

	for scanner.Scan() {
		line := scanner.Text()
		
		// Parse chunk size line (format: "size;chunk-signature=...")
		parts := strings.Split(line, ";")
		if len(parts) < 2 {
			continue
		}
		
		sizeStr := strings.TrimSpace(parts[0])
		chunkSize, err := strconv.ParseInt(sizeStr, 16, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid AWS chunk size: %s", sizeStr)
		}

		if chunkSize == 0 {
			break // End of chunks
		}

		// Read chunk data
		if !scanner.Scan() {
			return nil, fmt.Errorf("missing chunk data")
		}
		chunkData := scanner.Text()
		
		if int64(len(chunkData)) != chunkSize {
			return nil, fmt.Errorf("chunk data length mismatch: expected %d, got %d", chunkSize, len(chunkData))
		}
		
		result.WriteString(chunkData)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error processing AWS chunked data: %w", err)
	}

	return result.Bytes(), nil
}

// CreateOptimalReader creates a reader for AWS chunked data
func (d *AWSChunkedDecoder) CreateOptimalReader(r *http.Request) io.Reader {
	if !d.RequiresChunkedDecoding(r) {
		return r.Body
	}

	// Read all data and process
	data, err := io.ReadAll(r.Body)
	if err != nil {
		d.logger.WithError(err).Error("Failed to read AWS chunked data")
		return r.Body
	}

	processedData, err := d.ProcessChunkedData(data)
	if err != nil {
		d.logger.WithError(err).Error("Failed to process AWS chunked data")
		return bytes.NewReader(data)
	}

	return bytes.NewReader(processedData)
}

// GetName returns the decoder name
func (d *AWSChunkedDecoder) GetName() string {
	return "AWS-Chunked"
}
