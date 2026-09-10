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

// WriteXML writes an XML response
func (x *XMLWriter) WriteXML(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)

	if err := xml.NewEncoder(w).Encode(data); err != nil {
		x.logger.WithError(err).Error("Failed to write XML response")
	}
}

func (x *XMLWriter) WriteRawXML(w http.ResponseWriter, xmlContent string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)

	if _, err := w.Write([]byte(xmlContent)); err != nil {
		x.logger.WithError(err).Error("Failed to write raw XML response")
	}
}

// WriteS3Document writes an S3 response document: the XML declaration, then the
// marshalled body. It marshals BEFORE it commits a status, so a marshalling
// failure answers 500 instead of leaving a truncated document behind a 200 that
// has already gone out.
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
