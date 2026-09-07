package response

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RespStatusOnlyError builds the chain a backend produces when it answered with
// an HTTP status but a body the SDK could not parse into an <Error> document:
// a *awshttp.ResponseError carrying the status, wrapping a plain error. This is
// the only way codeForStatus is reached, because MapError derives the code from
// the chain and only falls back to the status when no APIError is present.
func RespStatusOnlyError(status int) error {
	return &awshttp.ResponseError{
		ResponseError: &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{Response: &http.Response{StatusCode: status}},
			Err:      errors.New("backend answered with an unparseable body"),
		},
		RequestID: "RESPCOVERAGE0001",
	}
}

// RespAPIErrorNoResponse is an SDK typed error that never carried an HTTP
// response: a caller-constructed error, or a transport that lost the response.
// The status then comes from the codeStatus table alone.
func RespAPIErrorNoResponse(code, message string) error {
	return &smithy.OperationError{
		ServiceID:     "S3",
		OperationName: "RespOperation",
		Err:           &smithy.GenericAPIError{Code: code, Message: message},
	}
}

// codeForStatus is the fallback that decides the S3 <Code> when the backend
// answered without a parseable one. Every branch is a distinct S3 code, and a
// client that branches on the code depends on all of them.
func TestRespMapErrorCodeForStatusFallback(t *testing.T) {
	cases := []struct {
		name        string
		status      int
		wantStatus  int
		wantCode    string
		wantMessage string
		wantInvalid bool
	}{
		// Statuses with a dedicated S3 code.
		{"404_not_found", 404, 404, "NotFound", "The specified resource does not exist", false},
		{"403_forbidden", 403, 403, "AccessDenied", "Access Denied", false},
		{"409_conflict", 409, 409, "OperationAborted", "Conflict", false},
		{"412_precondition", 412, 412, "PreconditionFailed", "At least one of the preconditions you specified did not hold", false},
		{"416_range", 416, 416, "InvalidRange", "The requested range is not satisfiable", false},
		{"501_not_implemented", 501, 501, "NotImplemented", "Not Implemented", true},
		{"503_unavailable", 503, 503, "ServiceUnavailable", "Service Unavailable", true},
		// Generic 4xx and 5xx buckets.
		{"400_generic", 400, 400, "InvalidRequest", "Bad Request", false},
		{"405_generic", 405, 405, "InvalidRequest", "Method Not Allowed", false},
		{"411_generic", 411, 411, "InvalidRequest", "Length Required", false},
		{"500_generic", 500, 500, "InternalError", "Internal Server Error", true},
		{"502_generic", 502, 502, "InternalError", "Bad Gateway", true},
		{"504_generic", 504, 504, "InternalError", "Gateway Timeout", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := MapError(RespStatusOnlyError(tc.status))
			assert.Equal(t, tc.wantStatus, got.StatusCode)
			assert.Equal(t, tc.wantCode, got.Code)
			assert.Equal(t, tc.wantMessage, got.Message)
			assert.Equal(t, tc.wantStatus >= http.StatusInternalServerError, got.Internal)
			// The unparseable backend body must never reach the client.
			assert.NotContains(t, got.Message, "unparseable")
			assert.NotContains(t, got.Message, "RESPCOVERAGE0001")
		})
	}
}

// A backend 5xx keeps the plain HTTP reason phrase, not the generic internal
// message: only errors that never reached the backend are opaque. Pinning this
// keeps a future "be opaque everywhere" edit from also hiding backend outages.
func TestRespMapErrorBackend5xxKeepsReasonPhrase(t *testing.T) {
	got := MapError(RespStatusOnlyError(http.StatusInternalServerError))
	assert.Equal(t, "Internal Server Error", got.Message)
	assert.NotEqual(t, genericInternalMessage, got.Message)
	assert.True(t, got.Internal)
}

// D-26: a backend answer that is not an error status is still an error, so the
// status is forced to 500 and a client that branches on the status alone cannot
// read the failure as a success. The normalization runs before the code and
// message fallbacks, so these also stop losing their <Message>.
func TestRespMapErrorNonErrorStatusesBecome500(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{"200_with_an_unparseable_body", RespStatusOnlyError(http.StatusOK)},
		{"302_the_proxy_cannot_forward", RespStatusOnlyError(http.StatusFound)},
		// net/http answers a 1xx as an informational response without
		// committing the status, so the body write then commits an implicit
		// 200 carrying the <Error> document - the reported bug itself.
		{"100_would_commit_an_implicit_200", RespStatusOnlyError(http.StatusContinue)},
		{"999_is_not_a_status", RespStatusOnlyError(999)},
		{"99_is_not_a_status", RespStatusOnlyError(99)},
		{
			// The reachable production shape: the SDK wraps a deserialization
			// failure on an otherwise successful 200 into *awshttp.ResponseError
			// carrying that 200. smithy.DeserializationError is not an
			// APIError, so MapError has only the status to go on.
			"sdk_deserialization_failure_on_200",
			&smithy.OperationError{
				ServiceID:     "S3",
				OperationName: "GetBucketLocation",
				Err: &awshttp.ResponseError{
					ResponseError: &smithyhttp.ResponseError{
						Response: &smithyhttp.Response{Response: &http.Response{StatusCode: http.StatusOK}},
						Err:      &smithy.DeserializationError{Err: errors.New("unexpected EOF")},
					},
					RequestID: "RESPCOVERAGE0002",
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := MapError(tc.err)

			assert.Equal(t, http.StatusInternalServerError, got.StatusCode)
			assert.Equal(t, "InternalError", got.Code)
			assert.Equal(t, "Internal Server Error", got.Message,
				"the message is derived after the status is forced, so it is never empty")
			assert.True(t, got.Internal, "and it is logged at error level")
		})
	}
}

// The one status below 400 that survives: 304 is the answer to a conditional
// read, not a failure. handleGetObject forwards If-None-Match, so a revalidating
// client depends on getting its 304 back rather than a 500.
func TestRespMapErrorNotModifiedIsForwarded(t *testing.T) {
	t.Run("with_the_code_the_sdk_derives", func(t *testing.T) {
		got := MapError(&smithy.OperationError{
			ServiceID:     "S3",
			OperationName: "GetObject",
			Err: &awshttp.ResponseError{
				ResponseError: &smithyhttp.ResponseError{
					Response: &smithyhttp.Response{Response: &http.Response{StatusCode: http.StatusNotModified}},
					Err:      &smithy.GenericAPIError{Code: "NotModified", Message: "Not Modified"},
				},
				RequestID: "RESPCOVERAGE0003",
			},
		})

		assert.Equal(t, http.StatusNotModified, got.StatusCode)
		assert.Equal(t, "NotModified", got.Code)
		assert.False(t, got.Internal)
	})

	// Load-bearing for coverage as well: 304 is now the only status below 400
	// that reaches codeForStatus, so this is what keeps its trailing return
	// covered.
	t.Run("without_a_code_at_all", func(t *testing.T) {
		got := MapError(RespStatusOnlyError(http.StatusNotModified))

		assert.Equal(t, http.StatusNotModified, got.StatusCode)
		assert.Equal(t, "InternalError", got.Code)
		assert.False(t, got.Internal)
	})
}

// Every code in codeStatus must resolve to the HTTP status AWS documents for it
// when the error arrives without an HTTP response. A client that keys retries or
// bucket-creation logic off the status depends on each of these exactly.
func TestRespMapErrorCodeStatusTableMatchesAWS(t *testing.T) {
	// Written out rather than ranged over codeStatus, so a wrong edit to the
	// production table fails here instead of being mirrored by the test.
	want := map[string]int{
		"BadDigest":               400,
		"EntityTooLarge":          400,
		"EntityTooSmall":          400,
		"IncompleteBody":          400,
		"InvalidArgument":         400,
		"InvalidBucketName":       400,
		"InvalidDigest":           400,
		"InvalidPart":             400,
		"InvalidPartOrder":        400,
		"InvalidRequest":          400,
		"MalformedXML":            400,
		"MetadataTooLarge":        400,
		"MissingRequestBodyError": 400,
		"RequestTimeout":          400,

		"AccessDenied":          403,
		"AllAccessDisabled":     403,
		"InvalidAccessKeyId":    403,
		"RequestTimeTooSkewed":  403,
		"SignatureDoesNotMatch": 403,

		"NoSuchBucket":                                   404,
		"NoSuchBucketPolicy":                             404,
		"NoSuchCORSConfiguration":                        404,
		"NoSuchKey":                                      404,
		"NoSuchLifecycleConfiguration":                   404,
		"NoSuchTagSet":                                   404,
		"NoSuchUpload":                                   404,
		"NoSuchVersion":                                  404,
		"NoSuchWebsiteConfiguration":                     404,
		"NotFound":                                       404,
		"ObjectLockConfigurationNotFoundError":           404,
		"ReplicationConfigurationNotFoundError":          404,
		"ServerSideEncryptionConfigurationNotFoundError": 404,

		"MethodNotAllowed":        405,
		"BucketAlreadyExists":     409,
		"BucketAlreadyOwnedByYou": 409,
		"BucketNotEmpty":          409,
		"OperationAborted":        409,
		"MissingContentLength":    411,
		"PreconditionFailed":      412,
		"InvalidRange":            416,

		"InternalError":      500,
		"NotImplemented":     501,
		"ServiceUnavailable": 503,
		"SlowDown":           503,
	}

	require.Len(t, codeStatus, len(want), "codeStatus gained or lost an entry: extend this table")

	for code, status := range want {
		t.Run(code, func(t *testing.T) {
			got := MapError(RespAPIErrorNoResponse(code, "backend said so"))
			assert.Equal(t, status, got.StatusCode)
			assert.Equal(t, code, got.Code, "the backend code must survive verbatim")
			assert.Equal(t, "backend said so", got.Message)
			assert.Equal(t, status >= 500, got.Internal)
		})
	}
}

// An empty <Message> from the backend is filled from codeMessage, and only
// falls back to the HTTP reason phrase for codes that have no canonical wording.
func TestRespMapErrorEmptyMessageFallback(t *testing.T) {
	cases := []struct {
		code        string
		wantMessage string
	}{
		// Canonical S3 wording from codeMessage.
		{"AccessDenied", "Access Denied"},
		{"BucketAlreadyExists", "The requested bucket name is not available"},
		{"BucketAlreadyOwnedByYou", "Your previous request to create the named bucket succeeded and you already own it"},
		{"BucketNotEmpty", "The bucket you tried to delete is not empty"},
		{"InvalidBucketName", "The specified bucket is not valid"},
		{"InvalidPart", "One or more of the specified parts could not be found"},
		{"InvalidRange", "The requested range is not satisfiable"},
		{"NoSuchBucket", "The specified bucket does not exist"},
		{"NoSuchKey", "The specified key does not exist"},
		{"NoSuchUpload", "The specified multipart upload does not exist"},
		{"NoSuchWebsiteConfiguration", "The specified bucket does not have a website configuration"},
		{"NotFound", "The specified resource does not exist"},
		{"PreconditionFailed", "At least one of the preconditions you specified did not hold"},
		// No canonical wording: the HTTP reason phrase for the mapped status.
		{"MalformedXML", "Bad Request"},
		{"SlowDown", "Service Unavailable"},
		{"MethodNotAllowed", "Method Not Allowed"},
		{"MissingContentLength", "Length Required"},
	}

	require.Len(t, codeMessage, 13, "codeMessage gained or lost an entry: extend this table")

	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			got := MapError(RespAPIErrorNoResponse(tc.code, ""))
			assert.Equal(t, tc.code, got.Code)
			assert.Equal(t, tc.wantMessage, got.Message)
			assert.NotEmpty(t, got.Message, "an S3 <Error> without a Message breaks clients that display it")
		})
	}
}

// A code the table does not know keeps its code but has no status to derive, so
// it is answered 500. Any S3 code AWS documents as a 4xx and that is missing
// from codeStatus therefore reaches the client as a server error.
func TestRespMapErrorUnknownCodeWithoutResponseIs500(t *testing.T) {
	for _, code := range []string{"InvalidToken", "AuthorizationHeaderMalformed", "PermanentRedirect", "RestoreAlreadyInProgress"} {
		t.Run(code, func(t *testing.T) {
			got := MapError(RespAPIErrorNoResponse(code, "m"))
			assert.Equal(t, http.StatusInternalServerError, got.StatusCode)
			assert.Equal(t, code, got.Code)
			assert.True(t, got.Internal)
		})
	}
}

// The HTTP status attached to the response always wins over the codeStatus
// table: the backend is the authority on what it answered.
func TestRespMapErrorResponseStatusBeatsTable(t *testing.T) {
	err := &awshttp.ResponseError{
		ResponseError: &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{Response: &http.Response{StatusCode: http.StatusForbidden}},
			// codeStatus maps NoSuchKey to 404, but the backend said 403.
			Err: &smithy.GenericAPIError{Code: "NoSuchKey", Message: "denied instead"},
		},
	}
	got := MapError(err)
	assert.Equal(t, http.StatusForbidden, got.StatusCode)
	assert.Equal(t, "NoSuchKey", got.Code)
	assert.Equal(t, "denied instead", got.Message)
	assert.False(t, got.Internal)
}

// An APIError that carries a message but no code still gets its code from the
// status, and keeps the backend message.
func TestRespMapErrorEmptyCodeWithResponseStatus(t *testing.T) {
	err := &awshttp.ResponseError{
		ResponseError: &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{Response: &http.Response{StatusCode: http.StatusNotFound}},
			Err:      &smithy.GenericAPIError{Code: "", Message: "nothing here"},
		},
	}
	got := MapError(err)
	assert.Equal(t, http.StatusNotFound, got.StatusCode)
	assert.Equal(t, "NotFound", got.Code)
	assert.Equal(t, "nothing here", got.Message)
}

// An APIError with neither code nor HTTP response is indistinguishable from a
// plain internal error and must stay opaque.
func TestRespMapErrorEmptyCodeWithoutResponseStaysOpaque(t *testing.T) {
	got := MapError(&smithy.GenericAPIError{Code: "", Message: "leaks the kek fingerprint ab12cd34"})
	assert.Equal(t, http.StatusInternalServerError, got.StatusCode)
	assert.Equal(t, "InternalError", got.Code)
	assert.Equal(t, genericInternalMessage, got.Message)
	assert.NotContains(t, got.Message, "ab12cd34")
	assert.True(t, got.Internal)
}

// Marker classification is a substring match over the whole error text, and it
// runs before the SDK chain is consulted. Both facts are load-bearing and both
// are sharp edges, so they are pinned: a marker found anywhere in the text wins
// over a real backend answer.
func TestRespMapErrorMarkerPrecedenceIsTextual(t *testing.T) {
	t.Run("marker_beats_backend_403", func(t *testing.T) {
		err := fmt.Errorf("decrypt failed: %w", RespWrapMarker(http.StatusForbidden, "KEK_MISSING"))
		got := MapError(err)
		assert.Equal(t, http.StatusUnprocessableEntity, got.StatusCode)
		assert.Equal(t, "DecryptionError", got.Code)
	})

	t.Run("marker_substring_in_unrelated_text", func(t *testing.T) {
		// No marker was raised here: the text merely contains one.
		got := MapError(errors.New("failed to stat /var/lib/s3ep/KEY_MISSING.report"))
		assert.Equal(t, http.StatusBadRequest, got.StatusCode)
		assert.Equal(t, "InvalidRequest", got.Code)
		assert.Equal(t, "Encryption key is missing or invalid", got.Message)
	})

	t.Run("first_marker_in_list_wins", func(t *testing.T) {
		// KEK_MISSING is listed before UNSUPPORTED_PROVIDER, so it decides.
		got := MapError(errors.New("KEK_MISSING and UNSUPPORTED_PROVIDER at once"))
		assert.Equal(t, http.StatusUnprocessableEntity, got.StatusCode)
		assert.Equal(t, "DecryptionError", got.Code)
	})

	t.Run("markers_are_case_sensitive", func(t *testing.T) {
		got := MapError(errors.New("kek_missing for object"))
		assert.Equal(t, http.StatusInternalServerError, got.StatusCode)
		assert.Equal(t, genericInternalMessage, got.Message)
	})
}

// RespWrapMarker builds a backend error whose message carries marker text.
func RespWrapMarker(status int, marker string) error {
	return &awshttp.ResponseError{
		ResponseError: &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{Response: &http.Response{StatusCode: status}},
			Err:      &smithy.GenericAPIError{Code: "AccessDenied", Message: marker},
		},
	}
}

// RespFailingWriter is an http.ResponseWriter whose Write always fails, the way
// a client that hung up mid-response behaves.
type RespFailingWriter struct {
	header http.Header
	Status int
	Writes int
}

func RespNewFailingWriter() *RespFailingWriter {
	return &RespFailingWriter{header: http.Header{}}
}

func (f *RespFailingWriter) Header() http.Header { return f.header }

func (f *RespFailingWriter) WriteHeader(status int) { f.Status = status }

func (f *RespFailingWriter) Write(_ []byte) (int, error) {
	f.Writes++
	return 0, errors.New("client hung up")
}

// A body write that fails must not panic and must not retry: the status and the
// Content-Type are already committed, and the failure belongs in the log.
func TestRespWriteErrorDocumentSurvivesFailedWrite(t *testing.T) {
	logger, hook := RespCapturingLogger()
	w := RespNewFailingWriter()

	NewErrorWriter(logger).WriteGenericError(w, http.StatusForbidden, "AccessDenied", "Access Denied")

	assert.Equal(t, http.StatusForbidden, w.Status)
	assert.Equal(t, "application/xml", w.Header().Get("Content-Type"))
	assert.Equal(t, 1, w.Writes, "a failed write must not be retried")

	entry := RespFindEntry(t, hook, "Failed to write error response")
	assert.Equal(t, "AccessDenied", entry.Data["error_code"])
	assert.EqualError(t, entry.Data[logrus.ErrorKey].(error), "client hung up")
}

// The same path through WriteS3Error, which is what handlers call.
func TestRespWriteS3ErrorSurvivesFailedWrite(t *testing.T) {
	logger, hook := RespCapturingLogger()
	w := RespNewFailingWriter()

	NewErrorWriter(logger).WriteS3Error(w, RespStatusOnlyError(http.StatusNotFound), "b", "k")

	assert.Equal(t, http.StatusNotFound, w.Status)
	entry := RespFindEntry(t, hook, "Failed to write error response")
	assert.Equal(t, "NotFound", entry.Data["error_code"])
}

// A 5xx is logged at error level, a client 4xx at warn: the log level is how an
// operator separates "our fault" from "their request".
func TestRespWriteS3ErrorLogLevels(t *testing.T) {
	cases := []struct {
		name      string
		err       error
		wantLevel logrus.Level
		wantMsg   string
	}{
		{"backend_404_is_warn", RespStatusOnlyError(http.StatusNotFound), logrus.WarnLevel, "S3 operation failed with client error"},
		{"backend_503_is_error", RespStatusOnlyError(http.StatusServiceUnavailable), logrus.ErrorLevel, "S3 operation failed"},
		{"internal_is_error", errors.New("kek fingerprint ab12 unavailable"), logrus.ErrorLevel, "S3 operation failed"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logger, hook := RespCapturingLogger()
			NewErrorWriter(logger).WriteS3Error(RespNewFailingWriter(), tc.err, "bucket", "key")

			entry := RespFindEntry(t, hook, tc.wantMsg)
			assert.Equal(t, tc.wantLevel, entry.Level)
			assert.Equal(t, "bucket", entry.Data["bucket"])
			assert.Equal(t, "key", entry.Data["key"])

			// The raw SDK text is debug-only and must not appear on the
			// operator-visible entry itself.
			assert.NotContains(t, entry.Message, "ab12")
		})
	}
}

// A nil error still reaches the writer from a mis-ordered handler; it must not
// log an error detail entry it has no error for.
func TestRespWriteS3ErrorNilErrorLogsNoDetail(t *testing.T) {
	logger, hook := RespCapturingLogger()
	logger.Logger.SetLevel(logrus.DebugLevel)

	NewErrorWriter(logger).WriteGenericError(RespNewFailingWriter(), http.StatusInternalServerError, "InternalError", genericInternalMessage)

	for _, e := range hook.AllEntries() {
		assert.NotEqual(t, "S3 operation error detail", e.Message)
	}
}

// RespCapturingLogger returns a logger whose entries can be inspected and whose
// output goes nowhere.
func RespCapturingLogger() (*logrus.Entry, *logrustest.Hook) {
	l := logrus.New()
	l.SetOutput(io.Discard)
	l.SetLevel(logrus.DebugLevel)
	hook := logrustest.NewLocal(l)
	return logrus.NewEntry(l), hook
}

// RespFindEntry returns the single log entry with the given message.
func RespFindEntry(t *testing.T, hook *logrustest.Hook, message string) *logrus.Entry {
	t.Helper()
	for _, e := range hook.AllEntries() {
		if e.Message == message {
			return e
		}
	}
	require.FailNowf(t, "log entry not found", "no entry with message %q", message)
	return nil
}
