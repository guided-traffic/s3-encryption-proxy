package response

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RespLocationPayload is a payload with an explicit XMLName, the shape an S3
// client expects on the wire.
type RespLocationPayload struct {
	XMLName xml.Name `xml:"LocationConstraint"`
	Value   string   `xml:",chardata"`
}

// RespTagPayload carries values that must survive XML escaping intact.
type RespTagPayload struct {
	XMLName xml.Name `xml:"Tag"`
	Key     string   `xml:"Key"`
	Value   string   `xml:"Value"`
}

// RespUnnamedPayload has no XMLName, so encoding/xml derives the element name
// from the Go type. Handlers pass AWS SDK output structs here, which is how a
// GetBucketLocationOutput ends up on the wire as <GetBucketLocationOutput>.
type RespUnnamedPayload struct {
	Field string
}

// RespTruncatingPayload marshals successfully for long enough to flush bytes to
// the client and then fails: encoding/xml rejects a channel field.
type RespTruncatingPayload struct {
	XMLName xml.Name `xml:"Truncating"`
	Head    string   `xml:"Head"`
	Bad     chan int `xml:"Bad"`
}

func TestRespNewXMLWriter(t *testing.T) {
	logger, _ := RespCapturingLogger()
	w := NewXMLWriter(logger)
	require.NotNil(t, w)
	assert.Same(t, logger, w.logger)
}

func TestRespWriteXML(t *testing.T) {
	logger, hook := RespCapturingLogger()
	rec := httptest.NewRecorder()

	NewXMLWriter(logger).WriteXML(rec, RespLocationPayload{Value: "eu-central-1"})

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/xml", rec.Header().Get("Content-Type"))
	assert.Equal(t, "<LocationConstraint>eu-central-1</LocationConstraint>", rec.Body.String())
	assert.Empty(t, hook.AllEntries(), "a successful write must log nothing")

	// The body is a complete document a client can parse back.
	var round RespLocationPayload
	require.NoError(t, xml.Unmarshal(rec.Body.Bytes(), &round))
	assert.Equal(t, "eu-central-1", round.Value)
}

// WriteXML emits no <?xml ...?> declaration, unlike the error document writer.
// Pinned because it is the kind of difference that silently breaks a strict
// client parser.
func TestRespWriteXMLHasNoXMLDeclaration(t *testing.T) {
	logger, _ := RespCapturingLogger()
	rec := httptest.NewRecorder()

	NewXMLWriter(logger).WriteXML(rec, RespLocationPayload{Value: "us-east-1"})

	assert.NotContains(t, rec.Body.String(), "<?xml")
	assert.True(t, strings.HasPrefix(rec.Body.String(), "<LocationConstraint>"))
}

// Values reach the body escaped, so a tag value containing markup cannot inject
// elements into the response or break the document.
func TestRespWriteXMLEscapesMarkup(t *testing.T) {
	logger, _ := RespCapturingLogger()
	rec := httptest.NewRecorder()

	hostile := `</Value><Injected>x</Injected><Value>a & b "q"`
	NewXMLWriter(logger).WriteXML(rec, RespTagPayload{Key: "k<1>", Value: hostile})

	body := rec.Body.String()
	assert.NotContains(t, body, "<Injected>")
	assert.Contains(t, body, "&lt;/Value&gt;")
	assert.Contains(t, body, "&amp;")

	// The value survives the round trip byte for byte, which is the point of
	// escaping rather than stripping.
	var round RespTagPayload
	require.NoError(t, xml.Unmarshal(rec.Body.Bytes(), &round))
	assert.Equal(t, hostile, round.Value)
	assert.Equal(t, "k<1>", round.Key)
}

// Without an XMLName the root element is the Go type name. Handlers hand AWS SDK
// output structs straight to WriteXML, so this is what decides the wire shape.
func TestRespWriteXMLUsesGoTypeNameWithoutXMLName(t *testing.T) {
	logger, _ := RespCapturingLogger()
	rec := httptest.NewRecorder()

	NewXMLWriter(logger).WriteXML(rec, RespUnnamedPayload{Field: "v"})

	assert.Equal(t, "<RespUnnamedPayload><Field>v</Field></RespUnnamedPayload>", rec.Body.String())
}

// A nil payload is not an error for encoding/xml: the client gets a 200 with an
// empty body and nothing is logged.
func TestRespWriteXMLNilPayload(t *testing.T) {
	logger, hook := RespCapturingLogger()
	rec := httptest.NewRecorder()

	NewXMLWriter(logger).WriteXML(rec, nil)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/xml", rec.Header().Get("Content-Type"))
	assert.Empty(t, rec.Body.String())
	assert.Empty(t, hook.AllEntries())
}

func TestRespWriteRawXML(t *testing.T) {
	logger, hook := RespCapturingLogger()
	rec := httptest.NewRecorder()

	raw := `<?xml version="1.0" encoding="UTF-8"?><CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin></CORSRule></CORSConfiguration>`
	NewXMLWriter(logger).WriteRawXML(rec, raw)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/xml", rec.Header().Get("Content-Type"))
	assert.Equal(t, raw, rec.Body.String(), "raw content must reach the client byte for byte")
	assert.Empty(t, hook.AllEntries())
}

// WriteRawXML performs no escaping at all: it is a verbatim pipe, so a caller
// that builds the string from request input owns the escaping.
func TestRespWriteRawXMLDoesNotEscape(t *testing.T) {
	logger, _ := RespCapturingLogger()
	rec := httptest.NewRecorder()

	raw := `<Tag><Value>a & b</Value></Tag>`
	NewXMLWriter(logger).WriteRawXML(rec, raw)

	assert.Equal(t, raw, rec.Body.String())
	assert.NotContains(t, rec.Body.String(), "&amp;")

	// The result is not well-formed XML, which is the risk this pins.
	var round RespTagPayload
	assert.Error(t, xml.Unmarshal(rec.Body.Bytes(), &round))
}

// A large body must arrive unchanged; compared by digest rather than dumped.
func TestRespWriteRawXMLLargeBodyIsByteExact(t *testing.T) {
	logger, _ := RespCapturingLogger()
	rec := httptest.NewRecorder()

	var b strings.Builder
	b.WriteString("<ListAllMyBucketsResult><Buckets>")
	for i := 0; i < 20000; i++ {
		b.WriteString("<Bucket><Name>bucket-")
		b.WriteString(strings.Repeat("x", 32))
		b.WriteString("</Name></Bucket>")
	}
	b.WriteString("</Buckets></ListAllMyBucketsResult>")
	raw := b.String()
	require.Greater(t, len(raw), 1<<20)

	NewXMLWriter(logger).WriteRawXML(rec, raw)

	want := sha256.Sum256([]byte(raw))
	got := sha256.Sum256(rec.Body.Bytes())
	assert.Equal(t, hex.EncodeToString(want[:]), hex.EncodeToString(got[:]))
	assert.Equal(t, http.StatusOK, rec.Code)
}

// A client that hangs up mid-response must not panic the handler; the failure is
// logged once and swallowed.
func TestRespWriteXMLLogsWriteFailure(t *testing.T) {
	cases := []struct {
		name    string
		call    func(x *XMLWriter, w http.ResponseWriter)
		want    int
		wantLog string
	}{
		{"WriteXML", func(x *XMLWriter, w http.ResponseWriter) {
			x.WriteXML(w, RespLocationPayload{Value: "eu-central-1"})
		}, http.StatusOK, "Failed to write XML response"},
		{"WriteRawXML", func(x *XMLWriter, w http.ResponseWriter) {
			x.WriteRawXML(w, "<Ok/>")
		}, http.StatusOK, "Failed to write raw XML response"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logger, hook := RespCapturingLogger()
			w := RespNewFailingWriter()

			assert.NotPanics(t, func() { tc.call(NewXMLWriter(logger), w) })

			assert.Equal(t, tc.want, w.Status)
			assert.Equal(t, "application/xml", w.Header().Get("Content-Type"))
			assert.Equal(t, 1, w.Writes, "a failed write must not be retried")

			entry := RespFindEntry(t, hook, tc.wantLog)
			assert.Equal(t, logrus.ErrorLevel, entry.Level)
			assert.EqualError(t, entry.Data[logrus.ErrorKey].(error), "client hung up")
		})
	}
}

// Documents a defect: WriteXML commits the status before it knows whether the
// payload can be marshalled, so a marshalling failure leaves the client with a
// 200 and a truncated document. The error writer avoids exactly this by
// marshalling first (errors.go writeErrorDocument).
func TestRespWriteXMLCommitsStatusBeforeMarshalCanFail(t *testing.T) {
	t.Run("failure_before_any_output", func(t *testing.T) {
		logger, hook := RespCapturingLogger()
		rec := httptest.NewRecorder()

		NewXMLWriter(logger).WriteXML(rec, make(chan int))

		assert.Equal(t, http.StatusOK, rec.Code, "success status already sent")
		assert.Equal(t, "application/xml", rec.Header().Get("Content-Type"))
		assert.Empty(t, rec.Body.String(), "client sees an empty body behind a 200")

		entry := RespFindEntry(t, hook, "Failed to write XML response")
		assert.Contains(t, entry.Data[logrus.ErrorKey].(error).Error(), "unsupported type")
	})

	t.Run("failure_after_partial_output", func(t *testing.T) {
		logger, hook := RespCapturingLogger()
		rec := httptest.NewRecorder()

		// Long enough to push the encoder past its internal buffer, so real
		// bytes reach the client before the failure.
		payload := RespTruncatingPayload{Head: strings.Repeat("A", 8192)}
		NewXMLWriter(logger).WriteXML(rec, payload)

		assert.Equal(t, http.StatusOK, rec.Code)
		body := rec.Body.String()
		require.NotEmpty(t, body, "partial document already flushed to the client")
		assert.True(t, strings.HasPrefix(body, "<Truncating><Head>AAAA"))
		assert.NotContains(t, body, "</Truncating>", "the document is truncated, not merely empty")

		var round RespTruncatingPayload
		assert.Error(t, xml.Unmarshal(rec.Body.Bytes(), &round), "the client receives unparseable XML behind a 200")

		RespFindEntry(t, hook, "Failed to write XML response")
	})
}
