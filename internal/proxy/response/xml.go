package response

import (
	"encoding/xml"
	"net/http"

	"github.com/sirupsen/logrus"
)

// XMLWriter handles XML response writing
type XMLWriter struct {
	logger *logrus.Entry
}

// NewXMLWriter creates a new XML response writer
func NewXMLWriter(logger *logrus.Entry) *XMLWriter {
	return &XMLWriter{
		logger: logger,
	}
}

// WriteS3Document writes an S3 response document: the XML declaration, then the
// marshalled body. It marshals BEFORE it commits a status, so a marshalling
// failure answers 500 instead of leaving a truncated document behind a 200 that
// has already gone out.
//
// It is the only document writer left. WriteXML committed 200 and only then
// encoded, so a marshalling failure left a truncated body behind a success
// status, and it was handed aws-sdk-go-v2 output structs, which carry no XML
// tags - every bucket sub-resource GET answered a document named after a Go
// type. WriteRawXML wrote a hand-built string and existed only for the two
// fabricated mock responses the nil-backend branches produced.
func (x *XMLWriter) WriteS3Document(w http.ResponseWriter, data interface{}) {
	body, err := xml.Marshal(data)
	if err != nil {
		x.logger.WithError(err).Error("Failed to marshal S3 response document")
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(append([]byte(xml.Header), body...)); err != nil {
		x.logger.WithError(err).Error("Failed to write S3 response document")
	}
}
