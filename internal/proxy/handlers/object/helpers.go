package object

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gorilla/mux"
	"github.com/guided-traffic/s3-encryption-proxy/internal/monitoring"
	"github.com/guided-traffic/s3-encryption-proxy/internal/orchestration"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/etag"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/request"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
	"github.com/sirupsen/logrus"
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

// WriteSSEHeaders restates what the backend reported about its own encryption of
// the stored object. The client asked for it — the proxy forwards
// x-amz-server-side-encryption and its KMS key id on every write path — and
// without this proxy in the path S3 would answer it directly.
//
// It is restated, never proxied: a header describing the backend service passes
// through, a header describing the stored bytes does not, because the stored
// bytes are ciphertext and the client receives plaintext (ADR 0008 D1).
func WriteSSEHeaders(w http.ResponseWriter, algorithm types.ServerSideEncryption, kmsKeyID *string) {
	if algorithm != "" {
		w.Header().Set("x-amz-server-side-encryption", string(algorithm))
	}
	if v := aws.ToString(kmsKeyID); v != "" {
		w.Header().Set("x-amz-server-side-encryption-aws-kms-key-id", v)
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

// integrityReason names what failed, for the log field and the metric label. The
// second return says whether the error is an integrity failure at all: a copy
// that stops because the client went away is not one.
func integrityReason(err error) (string, bool) {
	switch {
	case errors.Is(err, orchestration.ErrForeignObject):
		return "foreign_object", true
	case errors.Is(err, orchestration.ErrKeyMaterialUnreadable):
		return "key_material", true
	case errors.Is(err, dataencryption.ErrNotWellFormed):
		return "stored_length", true
	case errors.Is(err, dataencryption.ErrCorrupt):
		return "authentication", true
	default:
		return "", false
	}
}

// reportStreamFault records a response body that stopped before the object did.
//
// The status line is out by the time the plaintext moves, so a fault here cannot
// become an error document - the proxy stops writing and the client sees a short
// body. That is the deliberate price of streaming (ADR 0003 D15), and it is why
// this has to be loud in both places an operator looks: a log line that names
// the object and what failed, and a counter that is otherwise zero. The request
// itself is still counted as the 200 it announced.
//
// A copy that failed because the client disconnected is not an integrity fault
// and is not counted as one.
func (h *Handler) reportStreamFault(r *http.Request, err error) {
	vars := mux.Vars(r)
	fields := logrus.Fields{"bucket": vars["bucket"], "key": vars["key"]}

	reason, isIntegrity := integrityReason(err)
	if !isIntegrity {
		h.logger.WithError(err).WithFields(fields).
			Warn("The response body stopped before the object ended")
		return
	}

	monitoring.RecordObjectIntegrityFailure(reason, monitoring.IntegrityPhaseMidStream)
	h.logger.WithError(err).WithFields(fields).WithField("reason", reason).
		Error("Object failed its integrity check mid-stream; the response was truncated " +
			"and the client has incomplete data")
}

// clientETag is what a client is told an object's entity tag is. Under an
// encrypting provider the backend's tag is the MD5 of the stored bytes, and the
// marker says so, because the bare shape claims to be a digest of the object's
// content (ADR 0032 D2). Under the exit provider the stored bytes are the
// plaintext, so nothing is marked (ADR 0032 D7).
func (h *Handler) clientETag(value string) string {
	if h.encryptionMgr == nil || h.encryptionMgr.IsExitProvider() {
		return value
	}
	return etag.Mark(value)
}

// readDocument reads an object sub-resource document under
// optimizations.max_request_document_size, answering the client itself when it
// cannot and reporting false. Same bound and same reason as the bucket
// sub-resources (ADR 0011 D5, ADR 0024 D4).
func readDocument(
	w http.ResponseWriter,
	r *http.Request,
	parser *request.Parser,
	errorWriter *response.ErrorWriter,
	logger *logrus.Entry,
	bucket, key string,
) ([]byte, bool) {
	body, err := parser.ReadDocument(r)
	if err == nil {
		return body, true
	}
	if errors.Is(err, request.ErrBodyTooLarge) {
		logger.WithFields(logrus.Fields{"bucket": bucket, "key": key}).
			Warn("Refusing a sub-resource document above optimizations.max_request_document_size")
		errorWriter.WriteGenericError(w, http.StatusBadRequest, "EntityTooLarge",
			"The request document exceeds the maximum size this proxy accepts")
		return nil, false
	}
	logger.WithError(err).WithFields(logrus.Fields{"bucket": bucket, "key": key}).
		Error("Failed to read the request document")
	errorWriter.WriteS3Error(w, err, bucket, key)
	return nil, false
}

// responseOverrides maps the six response-* query parameters S3 defines onto the
// headers they replace. They are what a presigned download URL uses to name a
// file and set its type, so they are applied rather than dropped (ADR 0007 D1).
var responseOverrides = map[string]string{
	"response-content-type":        "Content-Type",
	"response-content-disposition": "Content-Disposition",
	"response-content-encoding":    "Content-Encoding",
	"response-content-language":    "Content-Language",
	"response-cache-control":       "Cache-Control",
	"response-expires":             "Expires",
}

// applyResponseOverrides runs after the stored values are set, so what the
// request asked for wins over what the object carries.
func applyResponseOverrides(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	for param, header := range responseOverrides {
		if value := query.Get(param); value != "" {
			w.Header().Set(header, value)
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
