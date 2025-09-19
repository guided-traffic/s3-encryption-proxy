package request

import (
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
	var result bytes.Buffer

	for {
		// Read chunk size line
		line, err := d.readLine(reader)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("error reading chunk size line: %w", err)
		}

		// Parse chunk size line (format: "size;chunk-signature=...")
		parts := strings.Split(string(line), ";")
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

		// Read chunk data (exactly chunkSize bytes)
		chunkData := make([]byte, chunkSize)
		n, err := io.ReadFull(reader, chunkData)
		if err != nil {
			return nil, fmt.Errorf("failed to read chunk data: %w", err)
		}
		if int64(n) != chunkSize {
			return nil, fmt.Errorf("chunk data length mismatch: expected %d, got %d", chunkSize, n)
		}

		result.Write(chunkData)

		// Read trailing CRLF after chunk data
		d.readLine(reader) // consume trailing CRLF
	}

	return result.Bytes(), nil
}

// readLine reads a line ending with CRLF or LF
func (d *AWSChunkedDecoder) readLine(reader *bytes.Reader) ([]byte, error) {
	var line []byte
	for {
		b, err := reader.ReadByte()
		if err != nil {
			return line, err
		}
		if b == '\n' {
			// Remove trailing \r if present
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			return line, nil
		}
		line = append(line, b)
	}
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
