package request

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
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
