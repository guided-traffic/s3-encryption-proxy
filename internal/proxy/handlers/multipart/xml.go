package multipart

import (
	"encoding/xml"
	"net/http"

	"github.com/sirupsen/logrus"
)

// initiateMultipartUploadResult is the CreateMultipartUpload response document.
type initiateMultipartUploadResult struct {
	XMLName  xml.Name `xml:"InitiateMultipartUploadResult"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	UploadID string   `xml:"UploadId"`
}

// listPartsResult is the ListParts response document.
type listPartsResult struct {
	XMLName              xml.Name `xml:"ListPartsResult"`
	Bucket               string   `xml:"Bucket"`
	Key                  string   `xml:"Key"`
	UploadID             string   `xml:"UploadId"`
	StorageClass         string   `xml:"StorageClass"`
	PartNumberMarker     int      `xml:"PartNumberMarker"`
	NextPartNumberMarker int      `xml:"NextPartNumberMarker"`
	MaxParts             int      `xml:"MaxParts"`
	IsTruncated          bool     `xml:"IsTruncated"`
}

// completeMultipartUploadResult is the CompleteMultipartUpload response document.
type completeMultipartUploadResult struct {
	XMLName  xml.Name `xml:"CompleteMultipartUploadResult"`
	Location string   `xml:"Location"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	ETag     string   `xml:"ETag"`
}

// writeXMLDocument writes an S3 XML response: the declaration followed by doc.
// encoding/xml escapes every value, so a bucket, key or upload id containing &
// or < cannot break the document or inject elements into it. Object keys hold
// those characters in normal use, so concatenating them produced a body the
// client could not parse.
func writeXMLDocument(w http.ResponseWriter, logger *logrus.Entry, doc interface{}) {
	body, err := xml.MarshalIndent(doc, "", "    ")
	if err != nil {
		logger.WithError(err).Error("Failed to marshal XML response")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(append([]byte(xml.Header), body...)); err != nil {
		logger.WithError(err).Error("Failed to write XML response")
	}
}
