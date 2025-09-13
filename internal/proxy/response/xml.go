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

// WriteXMLWithStatus writes an XML response with a specific status code
func (x *XMLWriter) WriteXMLWithStatus(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(statusCode)

	if err := xml.NewEncoder(w).Encode(data); err != nil {
		x.logger.WithError(err).Error("Failed to write XML response")
	}
}

// WriteRawXML writes raw XML content
func (x *XMLWriter) WriteRawXML(w http.ResponseWriter, xmlContent string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)

	if _, err := w.Write([]byte(xmlContent)); err != nil {
		x.logger.WithError(err).Error("Failed to write raw XML response")
	}
}
