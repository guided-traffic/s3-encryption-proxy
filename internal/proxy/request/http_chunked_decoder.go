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

		// Parse chunk size line
		chunkSize, err := strconv.ParseInt(strings.TrimSpace(string(line)), 16, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid HTTP chunk size: %s", line)
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
		if _, err := d.readLine(reader); err != nil {
			// Log warning but continue - trailing CRLF might be missing in some cases
			d.logger.WithError(err).Debug("Failed to read trailing CRLF after chunk data")
		}
	}

	return result.Bytes(), nil
}

// readLine reads a line ending with CRLF or LF
func (d *HTTPChunkedDecoder) readLine(reader *bytes.Reader) ([]byte, error) {
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
