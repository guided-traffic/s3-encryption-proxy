package bucket

import (
	"encoding/xml"
	"time"
)

// The S3 listing documents, built explicitly rather than marshalled from the SDK
// output structure. Two reasons, and both are the point of ADR 0010: the SDK
// type is named after an operation and carries fields that have no business on
// the wire, and the proxy has to be able to state a size the backend did not
// choose.
//
// Element order below is the order MinIO emits, captured from a running backend
// rather than read out of the API reference. Only a schema-validating parser
// cares, and that parser is exactly the client this document exists for.
//
// No checksum element appears anywhere in these types. A backend checksum
// describes ciphertext, and the proxy stores no plaintext checksum a listing
// could report instead, so the honest answer is to emit none — the same rule
// that keeps GET and HEAD from forwarding one.

const s3Namespace = "http://s3.amazonaws.com/doc/2006-03-01/"

// lastModifiedFormat is what S3 emits: RFC 3339 with exactly three fractional
// digits. Go's time.Time marshals without them.
const lastModifiedFormat = "2006-01-02T15:04:05.000Z"

// listBucketResultV2 is the ListObjectsV2 response document.
type listBucketResultV2 struct {
	XMLName               xml.Name       `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListBucketResult"`
	Name                  string         `xml:"Name"`
	Prefix                string         `xml:"Prefix"`
	StartAfter            string         `xml:"StartAfter,omitempty"`
	ContinuationToken     string         `xml:"ContinuationToken,omitempty"`
	NextContinuationToken string         `xml:"NextContinuationToken,omitempty"`
	KeyCount              int32          `xml:"KeyCount"`
	MaxKeys               int32          `xml:"MaxKeys"`
	Delimiter             string         `xml:"Delimiter,omitempty"`
	IsTruncated           bool           `xml:"IsTruncated"`
	Contents              []objectEntry  `xml:"Contents"`
	CommonPrefixes        []commonPrefix `xml:"CommonPrefixes"`
	EncodingType          string         `xml:"EncodingType,omitempty"`
}

// listBucketResultV1 is the ListObjects (V1) response document. Same root
// element, no key count, and a marker where V2 has a continuation token.
type listBucketResultV1 struct {
	XMLName        xml.Name       `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListBucketResult"`
	Name           string         `xml:"Name"`
	Prefix         string         `xml:"Prefix"`
	Marker         string         `xml:"Marker"`
	NextMarker     string         `xml:"NextMarker,omitempty"`
	MaxKeys        int32          `xml:"MaxKeys"`
	Delimiter      string         `xml:"Delimiter,omitempty"`
	IsTruncated    bool           `xml:"IsTruncated"`
	Contents       []objectEntry  `xml:"Contents"`
	CommonPrefixes []commonPrefix `xml:"CommonPrefixes"`
	EncodingType   string         `xml:"EncodingType,omitempty"`
}

// objectEntry is one <Contents> element. Owner sits between Size and
// StorageClass, which is where S3 and MinIO both put it.
type objectEntry struct {
	Key          string      `xml:"Key"`
	LastModified string      `xml:"LastModified"`
	ETag         string      `xml:"ETag"`
	Size         int64       `xml:"Size"`
	Owner        *ownerEntry `xml:"Owner,omitempty"`
	StorageClass string      `xml:"StorageClass,omitempty"`
}

type commonPrefix struct {
	Prefix string `xml:"Prefix"`
}

// ownerEntry identifies the caller, never the backend account (ADR 0008). S3
// returns an opaque canonical id here; the proxy has no such id for its own
// clients and answers with the access key that authenticated the request.
type ownerEntry struct {
	ID          string `xml:"ID"`
	DisplayName string `xml:"DisplayName"`
}

// formatLastModified renders a timestamp the way S3 does. A nil time is the
// zero value, which S3 never emits and which no caller should reach.
func formatLastModified(t *time.Time) string {
	if t == nil {
		return time.Time{}.UTC().Format(lastModifiedFormat)
	}
	return t.UTC().Format(lastModifiedFormat)
}
