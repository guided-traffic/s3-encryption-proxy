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

// HTTPChunkedDecoder handles standard HTTP chunked encoding
type HTTPChunkedDecoder struct {
	*ChunkedDecoderBase
}

// NewHTTPChunkedDecoder creates a new HTTP chunked decoder
func NewHTTPChunkedDecoder(logger *logrus.Entry) *HTTPChunkedDecoder {
	return &HTTPChunkedDecoder{
		ChunkedDecoderBase: NewChunkedDecoderBase(logger),
	}
}

// RequiresChunkedDecoding checks if this is HTTP chunked encoding
func (d *HTTPChunkedDecoder) RequiresChunkedDecoding(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Transfer-Encoding"), "chunked")
}

// ProcessChunkedData processes HTTP chunked data and extracts content
func (d *HTTPChunkedDecoder) ProcessChunkedData(data []byte) ([]byte, error) {
	reader := bytes.NewReader(data)
	scanner := bufio.NewScanner(reader)
	var result bytes.Buffer

	for scanner.Scan() {
		line := scanner.Text()
		
		// Parse chunk size line
		chunkSize, err := strconv.ParseInt(strings.TrimSpace(line), 16, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid HTTP chunk size: %s", line)
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
		return nil, fmt.Errorf("error processing HTTP chunked data: %w", err)
	}

	return result.Bytes(), nil
}

// CreateOptimalReader creates a reader for HTTP chunked data
func (d *HTTPChunkedDecoder) CreateOptimalReader(r *http.Request) io.Reader {
	if !d.RequiresChunkedDecoding(r) {
		return r.Body
	}

	// Read all data and process
	data, err := io.ReadAll(r.Body)
	if err != nil {
		d.logger.WithError(err).Error("Failed to read HTTP chunked data")
		return r.Body
	}

	processedData, err := d.ProcessChunkedData(data)
	if err != nil {
		d.logger.WithError(err).Error("Failed to process HTTP chunked data")
		return bytes.NewReader(data)
	}

	return bytes.NewReader(processedData)
}

// GetName returns the decoder name
func (d *HTTPChunkedDecoder) GetName() string {
	return "HTTP-Chunked"
}
