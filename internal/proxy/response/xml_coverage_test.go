package response

import (
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

// WriteS3Document is the only document writer left. The two it replaced are
// gone: WriteXML committed 200 and only then encoded, so a marshalling failure
// left a truncated body behind a success status, and WriteRawXML existed only
// for the fabricated mock documents the nil-backend branches produced.
func TestRespWriteS3Document(t *testing.T) {
	t.Run("declaration, then the document", func(t *testing.T) {
		logger, _ := RespCapturingLogger()
		rec := httptest.NewRecorder()

		NewXMLWriter(logger).WriteS3Document(rec, RespLocationPayload{Value: "eu-central-1"})

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "application/xml", rec.Header().Get("Content-Type"))
		assert.Equal(t, xml.Header+"<LocationConstraint>eu-central-1</LocationConstraint>", rec.Body.String())
	})

	t.Run("markup in a value is escaped", func(t *testing.T) {
		logger, _ := RespCapturingLogger()
		rec := httptest.NewRecorder()
		const hostile = `</Value></Tag><Injected>x</Injected><Tag><Value>`

		NewXMLWriter(logger).WriteS3Document(rec, RespTagPayload{Key: "k<1>", Value: hostile})

		assert.NotContains(t, rec.Body.String(), "<Injected>")
		var round RespTagPayload
		require.NoError(t, xml.Unmarshal(rec.Body.Bytes(), &round))
		assert.Equal(t, hostile, round.Value, "the value survives the round trip intact")
	})

	// This is the property the writer exists for: a payload that cannot be
	// marshalled answers 500 with nothing written, rather than a truncated
	// document behind a 200 the client has already been told to trust.
	t.Run("a marshalling failure answers 500, not a truncated 200", func(t *testing.T) {
		logger, hook := RespCapturingLogger()
		rec := httptest.NewRecorder()

		NewXMLWriter(logger).WriteS3Document(rec, RespTruncatingPayload{Head: strings.Repeat("A", 8192)})

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
		assert.Empty(t, rec.Body.String(), "nothing partial reaches the client")
		RespFindEntry(t, hook, "Failed to marshal S3 response document")
	})

	t.Run("a client that hangs up is logged once, not retried", func(t *testing.T) {
		logger, hook := RespCapturingLogger()
		w := RespNewFailingWriter()

		assert.NotPanics(t, func() {
			NewXMLWriter(logger).WriteS3Document(w, RespLocationPayload{Value: "eu-central-1"})
		})

		assert.Equal(t, http.StatusOK, w.Status)
		assert.Equal(t, 1, w.Writes, "a failed write must not be retried")
		entry := RespFindEntry(t, hook, "Failed to write S3 response document")
		assert.Equal(t, logrus.ErrorLevel, entry.Level)
	})
}
