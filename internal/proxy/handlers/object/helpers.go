package object

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
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

// storedEntityHeaders are the entity headers S3 returns with an object. Expires
// is taken from the raw header the backend sent rather than from the SDK's
// parsed time, so a value the SDK could not parse is still echoed as stored.
type storedEntityHeaders struct {
	ContentEncoding    *string
	ContentDisposition *string
	ContentLanguage    *string
	CacheControl       *string
	Expires            *string
}

// writeEntityHeaders emits the entity headers stored with the object. They
// describe the plaintext, so they survive encryption unchanged, and GET and HEAD
// answer with the same set: a GET that drops them contradicts its own HEAD.
func writeEntityHeaders(w http.ResponseWriter, e storedEntityHeaders) {
	for header, value := range map[string]*string{
		"Content-Encoding":    e.ContentEncoding,
		"Content-Disposition": e.ContentDisposition,
		"Content-Language":    e.ContentLanguage,
		"Cache-Control":       e.CacheControl,
		"Expires":             e.Expires,
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
// lowercase at startup (ADR 0009 D2), so lowering the key is enough to compare
// the two.
func (h *Handler) isEncryptionMetadata(key string) bool {
	return strings.HasPrefix(strings.ToLower(key), h.metadataPrefix)
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

// UserMetadata collects the client's own metadata headers. Keys are lowered
// because S3 lowers them in transit anyway, and a key inside the proxy's
// namespace is refused: that namespace is the proxy's alone, and storing such a
// key would collide with the proxy's own metadata at the backend and leave the
// object undecryptable (ADR 0009 D6).
//
// It is exported because every write path applies the one rule — the
// single-request PUT, the internal producer and client-driven
// CreateMultipartUpload — and a check a path can forget is how the case-sensitive
// hole survived on one of them.
func UserMetadata(r *http.Request, metadataPrefix string) (map[string]string, error) {
	metadata := make(map[string]string)
	for headerName, headerValues := range r.Header {
		if len(headerValues) == 0 || len(headerName) <= 11 || strings.ToLower(headerName[:11]) != "x-amz-meta-" {
			continue
		}
		metaKey := strings.ToLower(headerName[11:])
		if strings.HasPrefix(metaKey, metadataPrefix) {
			return nil, fmt.Errorf(
				"the user metadata key x-amz-meta-%s lies inside the metadata namespace this proxy reserves for itself",
				metaKey)
		}
		metadata[metaKey] = headerValues[0]
	}
	return metadata, nil
}

func (h *Handler) userMetadataFromRequest(r *http.Request) (map[string]string, error) {
	return UserMetadata(r, h.metadataPrefix)
}
