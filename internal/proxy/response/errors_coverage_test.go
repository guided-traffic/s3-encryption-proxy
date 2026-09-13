package response

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The body and log assertions that used to cover utils.HandleS3Error, moved onto
// ErrorWriter.WriteS3Error when the two implementations of one error document
// were consolidated. Several of them are the only tests that assert their
// property at all — that no backend detail leaks, that a resource is escaped,
// that the status decides the log level — which is why they were re-pointed
// rather than deleted.

// UtlCaptureLogger returns a logger that writes structured JSON into buf, so a
// test can assert on the level and the fields of every emitted entry.
func UtlCaptureLogger(level logrus.Level) (*logrus.Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	logger := logrus.New()
	logger.SetOutput(buf)
	logger.SetLevel(level)
	logger.SetFormatter(&logrus.JSONFormatter{})
	return logger, buf
}

// UtlLogEntry is one decoded logrus JSON line.
type UtlLogEntry struct {
	Level      string `json:"level"`
	Msg        string `json:"msg"`
	Error      string `json:"error"`
	Bucket     string `json:"bucket"`
	Key        string `json:"key"`
	Message    string `json:"message"`
	ErrorCode  string `json:"error_code"`
	StatusCode int    `json:"status_code"`
}

// UtlDecodeLog decodes every JSON line written by UtlCaptureLogger.
func UtlDecodeLog(t *testing.T, buf *bytes.Buffer) []UtlLogEntry {
	t.Helper()
	var entries []UtlLogEntry
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var e UtlLogEntry
		require.NoError(t, json.Unmarshal([]byte(line), &e), "log line is not valid JSON: %s", line)
		entries = append(entries, e)
	}
	return entries
}

// UtlFindLog returns the first decoded entry whose message equals msg.
func UtlFindLog(entries []UtlLogEntry, msg string) (UtlLogEntry, bool) {
	for _, e := range entries {
		if e.Msg == msg {
			return e, true
		}
	}
	return UtlLogEntry{}, false
}

// UtlFailingWriter is a ResponseWriter whose body write always fails, which is
// what a client that disconnected mid-response looks like to a handler.
type UtlFailingWriter struct {
	header     http.Header
	status     int
	writeCalls int
	err        error
}

func UtlNewFailingWriter(err error) *UtlFailingWriter {
	return &UtlFailingWriter{header: http.Header{}, err: err}
}

func (w *UtlFailingWriter) Header() http.Header { return w.header }

func (w *UtlFailingWriter) WriteHeader(status int) { w.status = status }

func (w *UtlFailingWriter) Write(_ []byte) (int, error) {
	w.writeCalls++
	return 0, w.err
}

// UtlSDKError builds the error chain aws-sdk-go-v2 hands back for a failed
// operation: *smithy.OperationError -> *awshttp.ResponseError -> typed error.
// The RequestID in it is backend detail that must never reach a client.
func UtlSDKError(operation string, status int, requestID string, inner error) error {
	return &smithy.OperationError{
		ServiceID:     "S3",
		OperationName: operation,
		Err: &awshttp.ResponseError{
			ResponseError: &smithyhttp.ResponseError{
				Response: &smithyhttp.Response{Response: &http.Response{StatusCode: status}},
				Err:      inner,
			},
			RequestID: requestID,
		},
	}
}

// UtlParseErrorBody unmarshals a rendered error document and checks the XML
// declaration the S3 clients expect in front of it.
func UtlParseErrorBody(t *testing.T, body string) s3Error {
	t.Helper()
	require.True(t, strings.HasPrefix(body, xml.Header), "body must start with the XML declaration, got %q", body)

	var doc s3Error
	require.NoError(t, xml.Unmarshal([]byte(body), &doc))
	return doc
}

// A body write that fails must not panic and must be reported, and the status
// must already have been committed before the failing write.
func TestRespWriteS3Error_WriteFailureIsLogged(t *testing.T) {
	logger, buf := UtlCaptureLogger(logrus.DebugLevel)
	w := UtlNewFailingWriter(errors.New("connection reset by peer"))

	NewErrorWriter(logrus.NewEntry(logger)).WriteS3Error(w, &types.NoSuchKey{}, "test-bucket", "test-key")

	assert.Equal(t, http.StatusNotFound, w.status)
	assert.Equal(t, "application/xml", w.header.Get("Content-Type"))
	assert.Equal(t, 1, w.writeCalls)

	entries := UtlDecodeLog(t, buf)
	entry, found := UtlFindLog(entries, "Failed to write error response")
	require.True(t, found, "a failed response write must be logged, got %v", entries)
	assert.Equal(t, "error", entry.Level)
	assert.Contains(t, entry.Error, "connection reset by peer")
}

// The <Resource> element is built from bucket and key. The empty-bucket case is
// asserted as it behaves today: no Resource element at all.
func TestRespWriteS3Error_ResourceComposition(t *testing.T) {
	cases := []struct {
		name         string
		bucket       string
		key          string
		wantResource string
	}{
		{"bucket and key", "my-bucket", "path/to/obj.bin", "my-bucket/path/to/obj.bin"},
		{"bucket only", "my-bucket", "", "my-bucket"},
		{"key without bucket", "", "orphan-key", ""},
		{"neither", "", "", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logger, buf := UtlCaptureLogger(logrus.DebugLevel)
			w := httptest.NewRecorder()

			NewErrorWriter(logrus.NewEntry(logger)).WriteS3Error(w, &types.NoSuchKey{}, tc.bucket, tc.key)

			require.Equal(t, http.StatusNotFound, w.Code)
			doc := UtlParseErrorBody(t, w.Body.String())
			assert.Equal(t, tc.wantResource, doc.Resource)
			assert.Equal(t, "NoSuchKey", doc.Code)
			// ADR 0008 D12: the proxy omits a value it does not have instead of
			// inventing one, and the constant "proxy-request" identifies nothing.
			// Open: stay absent, or mint a real id echoed in x-amz-request-id.
			assert.Empty(t, doc.RequestID)

			// bucket and key are only logged when they carry something.
			entry, found := UtlFindLog(UtlDecodeLog(t, buf), "S3 operation failed with client error")
			require.True(t, found)
			assert.Equal(t, tc.bucket, entry.Bucket)
			assert.Equal(t, tc.key, entry.Key)
			assert.Equal(t, http.StatusNotFound, entry.StatusCode)
			// The one field lost when the two writers were consolidated: a
			// static "message" string per call site, already implied by the
			// error code and the operation, and duplicated at the one call site
			// that had it by the WithError(...).Error(...) line above it.
			assert.Empty(t, entry.Message)
		})
	}
}

// Bucket and key reach this code straight from the request line. XML metachars
// in them must be escaped, not able to forge extra elements.
func TestRespWriteS3Error_EscapesResource(t *testing.T) {
	logger, _ := UtlCaptureLogger(logrus.ErrorLevel)
	w := httptest.NewRecorder()

	bucket := `b&<ket`
	key := `</Resource><Code>AccessDenied</Code><Resource>`

	NewErrorWriter(logrus.NewEntry(logger)).WriteS3Error(w, &types.NoSuchKey{}, bucket, key)

	body := w.Body.String()
	assert.NotContains(t, body, "<Code>AccessDenied</Code>", "injected element must not survive escaping")
	assert.Equal(t, 1, strings.Count(body, "<Code>"), "exactly one Code element")

	doc := UtlParseErrorBody(t, body)
	assert.Equal(t, bucket+"/"+key, doc.Resource, "the escaped value must round-trip exactly")
	assert.Equal(t, "NoSuchKey", doc.Code)
}

// Backend identifiers are debugging material: they belong in the log and never
// in the response body.
func TestRespWriteS3Error_DoesNotLeakBackendDetail(t *testing.T) {
	const requestID = "UTLREQUESTID0001"
	logger, buf := UtlCaptureLogger(logrus.DebugLevel)
	w := httptest.NewRecorder()

	err := UtlSDKError("GetObject", http.StatusNotFound, requestID,
		&types.NoSuchKey{Message: aws.String("The specified key does not exist.")})
	require.Contains(t, err.Error(), requestID, "precondition: the raw SDK text carries the RequestID")

	NewErrorWriter(logrus.NewEntry(logger)).WriteS3Error(w, err, "test-bucket", "test-key")

	require.Equal(t, http.StatusNotFound, w.Code)
	body := w.Body.String()
	for _, leak := range []string{requestID, "HostID", "operation error", "https response error"} {
		assert.NotContains(t, body, leak)
	}

	doc := UtlParseErrorBody(t, body)
	assert.Equal(t, "NoSuchKey", doc.Code)
	assert.Equal(t, "The specified key does not exist.", doc.Message)

	detail, found := UtlFindLog(UtlDecodeLog(t, buf), "S3 operation error detail")
	require.True(t, found, "the raw error must still be available at debug level")
	assert.Contains(t, detail.Error, requestID)
	assert.Equal(t, "debug", detail.Level)
}

// Status decides the log level: a backend 4xx is the client's problem (warn), a
// 5xx or an internal failure is ours (error).
func TestRespWriteS3Error_StatusDrivesLogLevel(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
		wantLevel  string
		wantMsg    string
	}{
		{
			name:       "backend 404 logs as client error",
			err:        UtlSDKError("HeadObject", http.StatusNotFound, "ID404", &types.NotFound{}),
			wantStatus: http.StatusNotFound,
			wantCode:   "NotFound",
			wantLevel:  "warning",
			wantMsg:    "S3 operation failed with client error",
		},
		{
			name:       "backend 503 logs as server error",
			err:        UtlSDKError("PutObject", http.StatusServiceUnavailable, "ID503", &smithy.GenericAPIError{Code: "SlowDown", Message: "Please reduce your request rate."}),
			wantStatus: http.StatusServiceUnavailable,
			wantCode:   "SlowDown",
			wantLevel:  "error",
			wantMsg:    "S3 operation failed",
		},
		{
			name:       "missing KEK is a 422 the client can act on",
			err:        errors.New("decrypt object: KEK_MISSING for fingerprint abc123"),
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   "DecryptionError",
			wantLevel:  "warning",
			wantMsg:    "S3 operation failed with client error",
		},
		{
			name:       "unknown internal failure stays a generic 500",
			err:        errors.New("cipher: message authentication failed for /var/keys/aes.key"),
			wantStatus: http.StatusInternalServerError,
			wantCode:   "InternalError",
			wantLevel:  "error",
			wantMsg:    "S3 operation failed",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logger, buf := UtlCaptureLogger(logrus.DebugLevel)
			w := httptest.NewRecorder()

			NewErrorWriter(logrus.NewEntry(logger)).WriteS3Error(w, tc.err, "b", "k")

			require.Equal(t, tc.wantStatus, w.Code)
			doc := UtlParseErrorBody(t, w.Body.String())
			assert.Equal(t, tc.wantCode, doc.Code)
			assert.NotEmpty(t, doc.Message, "every error document needs a message")

			entry, found := UtlFindLog(UtlDecodeLog(t, buf), tc.wantMsg)
			require.True(t, found, "expected a %q entry", tc.wantMsg)
			assert.Equal(t, tc.wantLevel, entry.Level)
			assert.Equal(t, tc.wantCode, entry.ErrorCode)
			assert.Equal(t, tc.wantStatus, entry.StatusCode)
		})
	}
}

// An internal failure must not put its own text on the wire: those strings name
// key paths and backend endpoints.
func TestRespWriteS3Error_InternalTextStaysInternal(t *testing.T) {
	const secret = "/etc/s3ep/private-key.pem"
	logger, buf := UtlCaptureLogger(logrus.DebugLevel)
	w := httptest.NewRecorder()

	NewErrorWriter(logrus.NewEntry(logger)).WriteS3Error(w, fmt.Errorf("load KEK from %s: permission denied", secret), "b", "k")

	require.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NotContains(t, w.Body.String(), secret, "internal error text must not reach the client")

	doc := UtlParseErrorBody(t, w.Body.String())
	assert.Equal(t, "InternalError", doc.Code)
	assert.Equal(t, "We encountered an internal error. Please try again.", doc.Message)

	detail, found := UtlFindLog(UtlDecodeLog(t, buf), "S3 operation error detail")
	require.True(t, found)
	assert.Contains(t, detail.Error, secret, "the detail must still be recoverable from the log")
}

// A nil error still has to produce a valid document, and must not emit an empty
// "error detail" line.
func TestRespWriteS3Error_NilError(t *testing.T) {
	logger, buf := UtlCaptureLogger(logrus.DebugLevel)
	w := httptest.NewRecorder()

	NewErrorWriter(logrus.NewEntry(logger)).WriteS3Error(w, nil, "b", "")

	require.Equal(t, http.StatusInternalServerError, w.Code)
	doc := UtlParseErrorBody(t, w.Body.String())
	assert.Equal(t, "InternalError", doc.Code)
	assert.Equal(t, "b", doc.Resource)

	entries := UtlDecodeLog(t, buf)
	_, found := UtlFindLog(entries, "S3 operation error detail")
	assert.False(t, found, "no detail line without an error, got %v", entries)
	_, found = UtlFindLog(entries, "S3 operation failed")
	assert.True(t, found)
}
