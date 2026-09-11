package response

import (
	"errors"
	"net/http"
	"strings"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/smithy-go"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/request"
)

// genericInternalMessage is the only text an internal (non-backend) failure is
// allowed to expose. Internal error strings carry key fingerprints, backend
// endpoints and operation context, so they belong in the log, not in a response.
const genericInternalMessage = "We encountered an internal error. Please try again."

// MappedError is the client-facing rendering of an error: the HTTP status and
// the contents of the S3 <Error> document.
type MappedError struct {
	StatusCode int
	Code       string
	Message    string
	// Internal marks failures that did not come from the S3 backend. They are
	// logged at error level; backend 4xx answers are the client's business and
	// are logged at warn.
	Internal bool
}

// codeStatus maps S3 error codes to the HTTP status S3 answers them with. It is
// the fallback for backend errors that arrive without an HTTP response attached
// (a typed error constructed by a caller, or a transport that lost the response).
var codeStatus = map[string]int{
	// 400
	"BadDigest":               http.StatusBadRequest,
	"EntityTooLarge":          http.StatusBadRequest,
	"EntityTooSmall":          http.StatusBadRequest,
	"IncompleteBody":          http.StatusBadRequest,
	"InvalidArgument":         http.StatusBadRequest,
	"InvalidBucketName":       http.StatusBadRequest,
	"InvalidDigest":           http.StatusBadRequest,
	"InvalidPart":             http.StatusBadRequest,
	"InvalidPartOrder":        http.StatusBadRequest,
	"InvalidRequest":          http.StatusBadRequest,
	"MalformedXML":            http.StatusBadRequest,
	"MetadataTooLarge":        http.StatusBadRequest,
	"MissingRequestBodyError": http.StatusBadRequest,
	"RequestTimeout":          http.StatusBadRequest,
	// 403
	"AccessDenied":          http.StatusForbidden,
	"AllAccessDisabled":     http.StatusForbidden,
	"InvalidAccessKeyId":    http.StatusForbidden,
	"RequestTimeTooSkewed":  http.StatusForbidden,
	"SignatureDoesNotMatch": http.StatusForbidden,
	// 404
	"NoSuchBucket":                                   http.StatusNotFound,
	"NoSuchBucketPolicy":                             http.StatusNotFound,
	"NoSuchCORSConfiguration":                        http.StatusNotFound,
	"NoSuchKey":                                      http.StatusNotFound,
	"NoSuchLifecycleConfiguration":                   http.StatusNotFound,
	"NoSuchTagSet":                                   http.StatusNotFound,
	"NoSuchUpload":                                   http.StatusNotFound,
	"NoSuchVersion":                                  http.StatusNotFound,
	"NoSuchWebsiteConfiguration":                     http.StatusNotFound,
	"NotFound":                                       http.StatusNotFound,
	"ObjectLockConfigurationNotFoundError":           http.StatusNotFound,
	"ReplicationConfigurationNotFoundError":          http.StatusNotFound,
	"ServerSideEncryptionConfigurationNotFoundError": http.StatusNotFound,
	// 405 / 409 / 411 / 412 / 416
	"MethodNotAllowed":        http.StatusMethodNotAllowed,
	"BucketAlreadyExists":     http.StatusConflict,
	"BucketAlreadyOwnedByYou": http.StatusConflict,
	"BucketNotEmpty":          http.StatusConflict,
	"OperationAborted":        http.StatusConflict,
	"MissingContentLength":    http.StatusLengthRequired,
	"PreconditionFailed":      http.StatusPreconditionFailed,
	"InvalidRange":            http.StatusRequestedRangeNotSatisfiable,
	// 5xx
	"InternalError":      http.StatusInternalServerError,
	"NotImplemented":     http.StatusNotImplemented,
	"ServiceUnavailable": http.StatusServiceUnavailable,
	"SlowDown":           http.StatusServiceUnavailable,
}

// codeMessage supplies the canonical S3 wording for codes the backend answered
// with an empty <Message>.
var codeMessage = map[string]string{
	"AccessDenied":               "Access Denied",
	"BucketAlreadyExists":        "The requested bucket name is not available",
	"BucketAlreadyOwnedByYou":    "Your previous request to create the named bucket succeeded and you already own it",
	"BucketNotEmpty":             "The bucket you tried to delete is not empty",
	"InvalidBucketName":          "The specified bucket is not valid",
	"InvalidPart":                "One or more of the specified parts could not be found",
	"InvalidRange":               "The requested range is not satisfiable",
	"NoSuchBucket":               "The specified bucket does not exist",
	"NoSuchKey":                  "The specified key does not exist",
	"NoSuchUpload":               "The specified multipart upload does not exist",
	"NoSuchWebsiteConfiguration": "The specified bucket does not have a website configuration",
	"NotFound":                   "The specified resource does not exist",
	"PreconditionFailed":         "At least one of the preconditions you specified did not hold",
}

// internalMarkers maps proxy-internal failure markers to a deliberate
// client-facing answer. These are the only internal errors that get a specific
// response instead of the generic 500; each tells the client something it can
// act on. The marker text is produced by the orchestration layer.
var internalMarkers = []struct {
	marker  string
	status  int
	code    string
	message string
}{
	{"KEK_MISSING", http.StatusUnprocessableEntity, "DecryptionError",
		"Unable to decrypt object: Required encryption key not available"},
	{"KEY_MISSING", http.StatusBadRequest, "InvalidRequest",
		"Encryption key is missing or invalid"},
	{"UNSUPPORTED_PROVIDER", http.StatusBadRequest, "InvalidRequest",
		"Unsupported encryption provider"},
}

// MapError classifies err into the status, code and message the client sees.
//
// aws-sdk-go-v2 never hands back a typed error directly: it wraps it as
// *smithy.OperationError -> *awshttp.ResponseError -> *types.X. Everything here
// therefore unwraps with errors.As rather than type-switching on the value,
// which is what made every backend error surface as 500 InternalError before.
//
// The chain is the only source of the code: an error that carries neither an
// APIError nor an HTTP status is internal by definition and is answered
// 500 InternalError with the generic message, never mapped by its text.
func MapError(err error) MappedError {
	if err == nil {
		return MappedError{http.StatusInternalServerError, "InternalError", genericInternalMessage, true}
	}

	// A client checksum verdict outranks everything else: it is the proxy's own
	// finding about the request, it is the client's mistake rather than a proxy
	// failure, and it must never be reported as a 5xx an SDK would retry
	// (ADR 0012 D6). It is matched here rather than at each call site because it
	// can reach any of them — the verifier sits inside both body readers.
	if verdict, ok := checksumVerdict(err); ok {
		return verdict
	}

	// Proxy-internal markers win: they are more specific than anything the
	// backend could have said, and the backend was not involved.
	text := err.Error()
	for _, m := range internalMarkers {
		if strings.Contains(text, m.marker) {
			return MappedError{m.status, m.code, m.message, true}
		}
	}

	var code, message string
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code = apiErr.ErrorCode()
		message = apiErr.ErrorMessage()
	}

	status := 0
	var respErr *awshttp.ResponseError
	if errors.As(err, &respErr) {
		status = respErr.HTTPStatusCode()
	}

	if code == "" && status == 0 {
		// Not an SDK error: internal, and its text must not reach the client.
		return MappedError{http.StatusInternalServerError, "InternalError", genericInternalMessage, true}
	}

	// S3 models "no website configuration" as NoSuchBucket carrying a distinct
	// message. Clients branch on the code, so translate it.
	if code == "NoSuchBucket" && strings.Contains(message, "does not have a website configuration") {
		code = "NoSuchWebsiteConfiguration"
	}

	if status == 0 {
		if s, ok := codeStatus[code]; ok {
			status = s
		} else {
			status = http.StatusInternalServerError
		}
	}
	// A failed operation must never be answered with a status a client reads as
	// success, and never with one net/http cannot write.
	//
	// S3 answers CopyObject, CompleteMultipartUpload and UploadPartCopy with 200
	// and an <Error> document, and aws-sdk-go-v2 rewrites such an answer to 500
	// before deserializing. It does that only for the operations that register
	// the customization - 88 of them in service/s3 v1.111.0 - and the ones it
	// leaves out are precisely this proxy's data plane: GetObject, PutObject,
	// UploadPart, HeadObject, DeleteObject, ListObjectsV2 and
	// CreateMultipartUpload register nothing, so for them a backend 2xx carrying
	// an error reaches this function unchanged. On top of that: a 1xx or 2xx
	// whose body failed to deserialize, and a 3xx this proxy cannot forward.
	//
	// A 1xx is the worst of them. net/http answers it as an informational
	// response without committing the status, so the body write then commits an
	// implicit 200 carrying the <Error> document. Below 100 WriteHeader panics,
	// and above 599 is not a status at all.
	//
	// Only the status is forced; the backend's code and message survive.
	//
	// 304 is the exception. It is the answer to a conditional read, not a
	// failure: handleGetObject forwards If-None-Match, so a revalidating client
	// depends on getting its 304 back.
	//
	// This runs before the code and message fallbacks below, so a forced 500
	// also derives "InternalError" rather than keeping a <Message> of "OK".
	if status > 599 || (status < http.StatusBadRequest && status != http.StatusNotModified) {
		status = http.StatusInternalServerError
	}

	if code == "" {
		code = codeForStatus(status)
	}
	if message == "" {
		if m, ok := codeMessage[code]; ok {
			message = m
		} else {
			message = http.StatusText(status)
		}
	}

	return MappedError{status, code, message, status >= http.StatusInternalServerError}
}

// codeForStatus derives an S3 error code from an HTTP status when the backend
// answered without a parseable <Code>.
func codeForStatus(status int) string {
	switch status {
	case http.StatusNotFound:
		return "NotFound"
	case http.StatusForbidden:
		return "AccessDenied"
	case http.StatusConflict:
		return "OperationAborted"
	case http.StatusPreconditionFailed:
		return "PreconditionFailed"
	case http.StatusRequestedRangeNotSatisfiable:
		return "InvalidRange"
	case http.StatusNotImplemented:
		return "NotImplemented"
	case http.StatusServiceUnavailable:
		return "ServiceUnavailable"
	}
	if status >= 500 {
		return "InternalError"
	}
	if status >= 400 {
		return "InvalidRequest"
	}
	return "InternalError"
}

// Client-facing wording for a checksum verdict. Both are AWS's own texts, and
// like every other code in this package the message is fixed: the verifier's
// error names the declaration that failed, and that belongs in the log.
const (
	badDigestMessage     = "The Content-MD5 or checksum value that you specified did not match what the server received."
	invalidDigestMessage = "The Content-MD5 or checksum value that you specified is not valid."
)

// checksumVerdict renders a client upload checksum failure, and reports whether
// err was one.
func checksumVerdict(err error) (MappedError, bool) {
	malformed, ok := request.IsChecksumFailure(err)
	if !ok {
		return MappedError{}, false
	}
	if malformed {
		return MappedError{http.StatusBadRequest, "InvalidDigest", invalidDigestMessage, false}, true
	}
	return MappedError{http.StatusBadRequest, "BadDigest", badDigestMessage, false}, true
}
