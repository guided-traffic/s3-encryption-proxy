package response

import (
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrorWriter_WriteNotSupportedWithEncryption(t *testing.T) {
	// Create a test logger
	logger := logrus.NewEntry(logrus.New())

	// Create error writer
	errorWriter := NewErrorWriter(logger)

	// Create test HTTP response writer
	w := httptest.NewRecorder()

	// Call the method
	errorWriter.WriteNotSupportedWithEncryption(w, "TestOperation")

	// Check status code
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)

	// Check content type
	assert.Equal(t, "application/xml", w.Header().Get("Content-Type"))

	// Check response body
	body, err := io.ReadAll(w.Body)
	assert.NoError(t, err)

	bodyStr := string(body)
	assert.Contains(t, bodyStr, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
	assert.Contains(t, bodyStr, "<Code>NotSupportedWithEncryption</Code>")
	assert.Contains(t, bodyStr, "<Message>TestOperation operation is not supported when encryption is enabled")
	assert.Contains(t, bodyStr, "Encrypted objects cannot use S3 server-side copy functionality")
	assert.Contains(t, bodyStr, "<Resource>TestOperation</Resource>")
}

func TestErrorWriter_WriteNotSupportedWithEncryption_CopyObject(t *testing.T) {
	// Create a test logger
	logger := logrus.NewEntry(logrus.New())

	// Create error writer
	errorWriter := NewErrorWriter(logger)

	// Create test HTTP response writer
	w := httptest.NewRecorder()

	// Call the method for CopyObject operation
	errorWriter.WriteNotSupportedWithEncryption(w, "CopyObject")

	// Check status code
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)

	// Check response body contains the right operation name
	body, err := io.ReadAll(w.Body)
	assert.NoError(t, err)

	bodyStr := string(body)
	assert.Contains(t, bodyStr, "CopyObject operation is not supported when encryption is enabled")
	assert.Contains(t, bodyStr, "<Resource>CopyObject</Resource>")
}

func TestErrorWriter_WriteNotSupportedWithEncryption_UploadPartCopy(t *testing.T) {
	// Create a test logger
	logger := logrus.NewEntry(logrus.New())

	// Create error writer
	errorWriter := NewErrorWriter(logger)

	// Create test HTTP response writer
	w := httptest.NewRecorder()

	// Call the method for UploadPartCopy operation
	errorWriter.WriteNotSupportedWithEncryption(w, "UploadPartCopy")

	// Check status code
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)

	// Check response body contains the right operation name
	body, err := io.ReadAll(w.Body)
	assert.NoError(t, err)

	bodyStr := string(body)
	assert.Contains(t, bodyStr, "UploadPartCopy operation is not supported when encryption is enabled")
	assert.Contains(t, bodyStr, "<Resource>UploadPartCopy</Resource>")
}

func TestErrorWriter_WriteNotSupportedWithEncryption_XMLFormat(t *testing.T) {
	// Create a test logger
	logger := logrus.NewEntry(logrus.New())

	// Create error writer
	errorWriter := NewErrorWriter(logger)

	// Create test HTTP response writer
	w := httptest.NewRecorder()

	// Call the method
	errorWriter.WriteNotSupportedWithEncryption(w, "TestOp")

	// Check that XML is properly formatted
	body, err := io.ReadAll(w.Body)
	assert.NoError(t, err)

	bodyStr := string(body)

	// Verify XML structure
	assert.True(t, strings.HasPrefix(bodyStr, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"))
	assert.Contains(t, bodyStr, "<Error>")
	assert.Contains(t, bodyStr, "</Error>")
	assert.Contains(t, bodyStr, "<Code>NotSupportedWithEncryption</Code>")
	assert.Contains(t, bodyStr, "<Message>")
	assert.Contains(t, bodyStr, "</Message>")
	assert.Contains(t, bodyStr, "<Resource>TestOp</Resource>")
}

// hostileText is what an S3 resource can legitimately carry: & and < are valid
// in object keys, and the trailing segments are the element injection the
// concatenated document allowed.
const hostileText = `a&b<c>"d"</Error><Injected/>`

// errorDocument is the wire shape of an S3 <Error>, declared here rather than
// reusing s3Error so the assertions below check what a client receives.
type errorDocument struct {
	XMLName  xml.Name `xml:"Error"`
	Code     string   `xml:"Code"`
	Message  string   `xml:"Message"`
	Resource string   `xml:"Resource"`
}

// decodeErrorDocument parses the body as an S3 <Error> document. Parsing is the
// load-bearing assertion here: the concatenated version did not parse at all.
func decodeErrorDocument(t *testing.T, body string) errorDocument {
	t.Helper()
	var doc errorDocument
	require.NoError(t, xml.Unmarshal([]byte(body), &doc), "error document must be well formed: %s", body)
	return doc
}

func TestErrorWriter_HostileInputStaysWellFormedXML(t *testing.T) {
	writer := NewErrorWriter(logrus.NewEntry(discardLogger()))

	t.Run("WriteS3Error escapes bucket and key", func(t *testing.T) {
		w := httptest.NewRecorder()
		writer.WriteS3Error(w, sdkError("GetObject", http.StatusNotFound, &types.NoSuchKey{}), "bucket"+hostileText, "key"+hostileText)

		body := w.Body.String()
		doc := decodeErrorDocument(t, body)
		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Equal(t, "NoSuchKey", doc.Code)
		assert.Equal(t, "bucket"+hostileText+"/key"+hostileText, doc.Resource)
		assert.NotContains(t, body, "<Injected/>")
	})

	t.Run("WriteGenericError escapes the message", func(t *testing.T) {
		w := httptest.NewRecorder()
		writer.WriteGenericError(w, http.StatusBadRequest, "InvalidRequest", hostileText)

		body := w.Body.String()
		doc := decodeErrorDocument(t, body)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, "InvalidRequest", doc.Code)
		assert.Equal(t, hostileText, doc.Message)
		assert.NotContains(t, body, "<Injected/>")
	})

	t.Run("WriteNotImplemented escapes the operation", func(t *testing.T) {
		w := httptest.NewRecorder()
		writer.WriteNotImplemented(w, "Op"+hostileText)

		body := w.Body.String()
		doc := decodeErrorDocument(t, body)
		assert.Equal(t, http.StatusNotImplemented, w.Code)
		assert.Equal(t, "NotImplemented", doc.Code)
		assert.Equal(t, "Op"+hostileText, doc.Resource)
		assert.NotContains(t, body, "<Injected/>")
	})

	t.Run("WriteNotSupportedWithEncryption escapes the operation", func(t *testing.T) {
		w := httptest.NewRecorder()
		writer.WriteNotSupportedWithEncryption(w, "Op"+hostileText)

		body := w.Body.String()
		doc := decodeErrorDocument(t, body)
		assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
		assert.Equal(t, "NotSupportedWithEncryption", doc.Code)
		assert.Equal(t, "Op"+hostileText, doc.Resource)
		assert.NotContains(t, body, "<Injected/>")
	})
}

// html.EscapeString, which these two writers used, covers & < > " ' but passes
// control characters through untouched. A key reachable over the URL path as
// /bucket/key%0Cname therefore produced a body no client could parse.
func TestErrorWriter_ControlCharacterStaysWellFormed(t *testing.T) {
	writer := NewErrorWriter(logrus.NewEntry(discardLogger()))

	t.Run("WriteS3Error", func(t *testing.T) {
		w := httptest.NewRecorder()
		writer.WriteS3Error(w, sdkError("GetObject", http.StatusNotFound, &types.NoSuchKey{}), "bucket", "key\x0cname")

		doc := decodeErrorDocument(t, w.Body.String())
		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Equal(t, "NoSuchKey", doc.Code)
		assert.Contains(t, doc.Resource, "bucket/key")
	})

	t.Run("WriteGenericError", func(t *testing.T) {
		w := httptest.NewRecorder()
		writer.WriteGenericError(w, http.StatusBadRequest, "InvalidRequest", "rejected key\x0cname")

		doc := decodeErrorDocument(t, w.Body.String())
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, "InvalidRequest", doc.Code)
		assert.Contains(t, doc.Message, "rejected key")
	})
}
