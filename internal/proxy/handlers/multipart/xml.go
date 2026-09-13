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

// s3Namespace is the document namespace S3 puts on a listing response.
const s3Namespace = "http://s3.amazonaws.com/doc/2006-03-01/"

// listPartsResult is the ListParts response document. Sizes are plaintext sizes
// (ADR 0010): the part the client uploaded, not what it occupies at the backend.
type listPartsResult struct {
	XMLName              xml.Name    `xml:"ListPartsResult"`
	XMLNS                string      `xml:"xmlns,attr"`
	Bucket               string      `xml:"Bucket"`
	Key                  string      `xml:"Key"`
	UploadID             string      `xml:"UploadId"`
	StorageClass         string      `xml:"StorageClass"`
	PartNumberMarker     int         `xml:"PartNumberMarker"`
	NextPartNumberMarker int         `xml:"NextPartNumberMarker"`
	MaxParts             int         `xml:"MaxParts"`
	IsTruncated          bool        `xml:"IsTruncated"`
	Owner                *ownerEntry `xml:"Owner,omitempty"`
	Parts                []partEntry `xml:"Part"`
}

// partEntry is one <Part> of a ListParts document.
type partEntry struct {
	PartNumber   int    `xml:"PartNumber"`
	LastModified string `xml:"LastModified,omitempty"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
}

// listMultipartUploadsResult is the ListMultipartUploads response document. It
// names uploads, not bytes, so nothing in it describes a stored size.
type listMultipartUploadsResult struct {
	XMLName            xml.Name       `xml:"ListMultipartUploadsResult"`
	XMLNS              string         `xml:"xmlns,attr"`
	Bucket             string         `xml:"Bucket"`
	KeyMarker          string         `xml:"KeyMarker"`
	UploadIDMarker     string         `xml:"UploadIdMarker"`
	NextKeyMarker      string         `xml:"NextKeyMarker"`
	NextUploadIDMarker string         `xml:"NextUploadIdMarker"`
	Delimiter          string         `xml:"Delimiter,omitempty"`
	Prefix             string         `xml:"Prefix,omitempty"`
	MaxUploads         int32          `xml:"MaxUploads"`
	IsTruncated        bool           `xml:"IsTruncated"`
	Uploads            []uploadEntry  `xml:"Upload"`
	CommonPrefixes     []commonPrefix `xml:"CommonPrefixes"`
}

// uploadEntry is one <Upload> of a ListMultipartUploads document.
type uploadEntry struct {
	Key          string      `xml:"Key"`
	UploadID     string      `xml:"UploadId"`
	Initiated    string      `xml:"Initiated,omitempty"`
	StorageClass string      `xml:"StorageClass,omitempty"`
	Owner        *ownerEntry `xml:"Owner,omitempty"`
	Initiator    *ownerEntry `xml:"Initiator,omitempty"`
}

type commonPrefix struct {
	Prefix string `xml:"Prefix"`
}

// ownerEntry describes the authenticated client. S3 puts an opaque canonical id
// in <Owner>; the proxy has none for its own clients and answers with the access
// key, which is the only identity it knows (ADR 0008).
type ownerEntry struct {
	ID          string `xml:"ID"`
	DisplayName string `xml:"DisplayName"`
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
