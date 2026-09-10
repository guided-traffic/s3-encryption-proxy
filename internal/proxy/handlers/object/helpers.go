package object

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/guided-traffic/s3-encryption-proxy/internal/orchestration"
)

// objectVersionID returns the versionId query parameter of an object request.
// S3 addresses one specific version with it on GET, HEAD and DELETE; dropping it
// serves or deletes the current version instead, which on a versioned bucket is
// a different object.
func objectVersionID(r *http.Request) *string {
	if v := r.URL.Query().Get("versionId"); v != "" {
		return aws.String(v)
	}
	return nil
}

// writeVersionHeaders forwards the versioning headers S3 returns. Without them a
// client on a versioned bucket cannot tell which version it read or wrote, nor
// that what it got was a delete marker. Only DeleteObject can report a delete
// marker on a successful response; GET and HEAD answer 404/405 for one, so those
// call sites pass nil.
func writeVersionHeaders(w http.ResponseWriter, versionID *string, deleteMarker *bool) {
	if v := aws.ToString(versionID); v != "" {
		w.Header().Set("x-amz-version-id", v)
	}
	if aws.ToBool(deleteMarker) {
		w.Header().Set("x-amz-delete-marker", "true")
	}
}

// writeEntityHeaders emits the entity headers stored with the object. They
// describe the plaintext, so they survive encryption unchanged, and HEAD already
// returns them: a GET that drops them contradicts its own HEAD.
func writeEntityHeaders(w http.ResponseWriter, output *s3.GetObjectOutput) {
	for header, value := range map[string]*string{
		"Content-Encoding":    output.ContentEncoding,
		"Content-Disposition": output.ContentDisposition,
		"Content-Language":    output.ContentLanguage,
		"Cache-Control":       output.CacheControl,
	} {
		if value != nil && *value != "" {
			w.Header().Set(header, *value)
		}
	}
}

const getResponseBufferSize = 128 * 1024

var getResponseBufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, getResponseBufferSize)
		return &b
	},
}

// writerOnly hides every optional interface of the writer it wraps, io.ReaderFrom
// above all. io.copyBuffer prefers dst.ReadFrom over the buffer it is handed, so
// without this the copy path was decided by how many middlewares happened to wrap
// the ResponseWriter rather than by measurement. Same device, same reason, as
// net/http's own writerOnly.
//
// It never leaves copyWithPooledBuffer: the handler keeps the original
// ResponseWriter, so nothing downstream loses Flusher, Hijacker or Unwrap.
type writerOnly struct{ io.Writer }

// copyWithPooledBuffer streams src into dst through a pooled 128 KiB buffer, in
// every configuration. The alternative it deliberately does not take is
// net/http's ResponseWriter.ReadFrom: the GET body is a decrypting reader, so
// neither sendfile nor splice can apply to it, and ReadFrom then degrades to a
// freshly allocated 32 KiB buffer per request on a plain HTTP/1 listener and is
// absent entirely under TLS and HTTP/2. Measured by BenchmarkGetResponseCopy.
func copyWithPooledBuffer(dst io.Writer, src io.Reader) (int64, error) {
	bufp := getResponseBufferPool.Get().(*[]byte)
	defer getResponseBufferPool.Put(bufp)
	return io.CopyBuffer(writerOnly{dst}, src, *bufp)
}

// extractEncryptionMetadata extracts encryption metadata from S3 object metadata
func (h *Handler) extractEncryptionMetadata(metadata map[string]string) (string, bool, bool) {
	if metadata == nil {
		return "", false, false
	}

	// Look for encrypted DEK metadata
	encryptedDEKB64, hasEncryption := metadata[h.metadataPrefix+"encrypted-dek"]
	if !hasEncryption {
		return "", false, false
	}

	// Check if this is streaming encryption by looking for streaming-specific metadata
	dekAlgorithm := metadata[h.metadataPrefix+"dek-algorithm"]
	isStreamingEncryption := dekAlgorithm == "aes-ctr" || dekAlgorithm == "AES-CTR"

	return encryptedDEKB64, true, isStreamingEncryption
}

// decodeEncryptedDEK decodes the base64-encoded encrypted DEK
func (h *Handler) decodeEncryptedDEK(encryptedDEKB64 string) ([]byte, error) {
	encryptedDEK, err := base64.StdEncoding.DecodeString(encryptedDEKB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted DEK: %w", err)
	}
	return encryptedDEK, nil
}

// cleanMetadata removes encryption-related metadata from the response
func (h *Handler) cleanMetadata(metadata map[string]string) map[string]string {
	if metadata == nil {
		return nil
	}

	cleaned := make(map[string]string)
	for key, value := range metadata {
		if !h.isEncryptionMetadata(key) {
			cleaned[key] = value
		}
	}

	if len(cleaned) == 0 {
		return nil
	}
	return cleaned
}

// isEncryptionMetadata reports whether a metadata key sits inside the proxy
// namespace. The comparison is case insensitive: net/http canonicalises request
// header names, so a client header x-amz-meta-s3ep-encrypted-dek arrives as
// X-Amz-Meta-S3ep-Encrypted-Dek and a case-sensitive check against the lowercase
// configured prefix never matched it. The configured prefix is validated as
// ^[a-z0-9-]+$ at startup, so lowering the key is enough to compare the two.
func (h *Handler) isEncryptionMetadata(key string) bool {
	return strings.HasPrefix(strings.ToLower(key), h.metadataPrefix)
}

// prepareEncryptionMetadata prepares encryption metadata for S3 storage
func (h *Handler) prepareEncryptionMetadata(r *http.Request, encResult *orchestration.EncryptionResult) map[string]string {
	metadata := make(map[string]string)

	// Add user metadata from request headers (case-insensitive check for x-amz-meta- headers).
	// The key is lowered because S3 lowers it in transit anyway, and because every
	// other collector of these headers does the same.
	for headerName, headerValues := range r.Header {
		if len(headerValues) > 0 && len(headerName) > 11 && strings.ToLower(headerName[:11]) == "x-amz-meta-" {
			metaKey := strings.ToLower(headerName[11:]) // Remove "X-Amz-Meta-" prefix
			if !h.isEncryptionMetadata(metaKey) {
				metadata[metaKey] = headerValues[0]
			}
		}
	}

	// Add encryption metadata
	for key, value := range encResult.Metadata {
		metadata[key] = value
	}

	return metadata
}

// addRequestHeaders adds relevant request headers to S3 input
func (h *Handler) addRequestHeaders(r *http.Request, input *s3.PutObjectInput) {
	// Add cache control
	if cacheControl := r.Header.Get("Cache-Control"); cacheControl != "" {
		input.CacheControl = aws.String(cacheControl)
	}

	// Add content disposition
	if contentDisposition := r.Header.Get("Content-Disposition"); contentDisposition != "" {
		input.ContentDisposition = aws.String(contentDisposition)
	}

	// Add content encoding
	if contentEncoding := StripAWSChunked(r.Header.Get("Content-Encoding")); contentEncoding != "" {
		input.ContentEncoding = aws.String(contentEncoding)
	}

	// Add content language
	if contentLanguage := r.Header.Get("Content-Language"); contentLanguage != "" {
		input.ContentLanguage = aws.String(contentLanguage)
	}
}

// getSegmentSize returns the configured streaming segment size
func (h *Handler) getSegmentSize() int64 {
	// Default segment size for streaming uploads (12MB)
	const defaultSegmentSize = 12 * 1024 * 1024

	if h.config != nil && h.config.Optimizations.StreamingSegmentSize > 0 {
		return h.config.Optimizations.StreamingSegmentSize
	}
	return defaultSegmentSize
}

// getMultipartUploadConcurrency returns the configured number of parallel
// S3 UploadPart workers used by putObjectAutoMultipart. Defaults to 4.
func (h *Handler) getMultipartUploadConcurrency() int {
	const defaultConcurrency = 4
	if h.config != nil && h.config.Optimizations.MultipartUploadConcurrency > 0 {
		return h.config.Optimizations.MultipartUploadConcurrency
	}
	return defaultConcurrency
}

// userMetadataFromRequest collects the client's own metadata headers. Keys are
// lowered because S3 lowers them in transit anyway, and keys inside the proxy's
// own namespace are dropped: that namespace is the proxy's alone (ADR 0009).
func (h *Handler) userMetadataFromRequest(r *http.Request) map[string]string {
	metadata := make(map[string]string)
	for headerName, headerValues := range r.Header {
		if len(headerValues) == 0 || len(headerName) <= 11 || strings.ToLower(headerName[:11]) != "x-amz-meta-" {
			continue
		}
		metaKey := strings.ToLower(headerName[11:])
		if !h.isEncryptionMetadata(metaKey) {
			metadata[metaKey] = headerValues[0]
		}
	}
	return metadata
}
