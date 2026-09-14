package response

import (
	"encoding/xml"
	"net/http"

	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/middleware"
	"github.com/sirupsen/logrus"
)

// s3Error is the S3 <Error> document. Marshalling through encoding/xml escapes
// every value, so a code, message or resource path containing & or < cannot
// break the document or inject elements into it. html.EscapeString, which this
// replaced, also passed control characters through untouched, so a key reached
// over the URL path as %0C produced a body no client could parse.
type s3Error struct {
	XMLName   xml.Name `xml:"Error"`
	Code      string   `xml:"Code"`
	Message   string   `xml:"Message"`
	Resource  string   `xml:"Resource,omitempty"`
	RequestID string   `xml:"RequestId,omitempty"`
}

// ErrorWriter handles S3 error responses
type ErrorWriter struct {
	logger *logrus.Entry
}

// NewErrorWriter creates a new error response writer
func NewErrorWriter(logger *logrus.Entry) *ErrorWriter {
	return &ErrorWriter{
		logger: logger,
	}
}

// WriteS3Error writes an S3 error response, mapping the error through MapError
// so that a backend 404 stays a 404 for the client instead of becoming a 500.
func (e *ErrorWriter) WriteS3Error(w http.ResponseWriter, err error, bucket, key string) {
	mapped := MapError(err)

	// A resource without a bucket names nothing, so it is omitted rather than
	// rendered as a leading slash.
	resource := bucket
	if bucket != "" && key != "" {
		resource = bucket + "/" + key
	} else if bucket == "" {
		resource = ""
	}

	logEntry := e.logger.WithFields(logrus.Fields{
		"bucket":      bucket,
		"key":         key,
		"error_code":  mapped.Code,
		"status_code": mapped.StatusCode,
	})
	// The raw SDK text carries backend RequestID, HostID and the operation name.
	// It is useful for debugging and must not reach the client, so it stays here.
	if err != nil {
		logEntry.WithError(err).Debug("S3 operation error detail")
	}
	if mapped.StatusCode >= http.StatusInternalServerError {
		logEntry.Error("S3 operation failed")
	} else {
		logEntry.Warn("S3 operation failed with client error")
	}

	e.writeErrorDocument(w, mapped.StatusCode, s3Error{
		Code:     mapped.Code,
		Message:  mapped.Message,
		Resource: resource,
	})
}

// writeErrorDocument renders doc as the response body. Marshalling happens
// before WriteHeader so a failure cannot leave a truncated body behind an
// already committed status.
func (e *ErrorWriter) writeErrorDocument(w http.ResponseWriter, statusCode int, doc s3Error) {
	// Read back off the response the id the request-id middleware stated, so the
	// document and the x-amz-request-id header always carry the same value
	// (ADR 0008 D12). Empty only where that middleware did not run, and the
	// element is then omitted rather than invented.
	doc.RequestID = w.Header().Get(middleware.RequestIDHeader)

	body, err := xml.MarshalIndent(doc, "", "    ")
	if err != nil {
		e.logger.WithError(err).WithField("error_code", doc.Code).Error("Failed to marshal error response")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(statusCode)
	if _, err := w.Write(append([]byte(xml.Header), body...)); err != nil {
		e.logger.WithError(err).WithField("error_code", doc.Code).Error("Failed to write error response")
	}
}

// WriteGenericError writes a generic error response with custom code and message
func (e *ErrorWriter) WriteGenericError(w http.ResponseWriter, statusCode int, code, message string) {
	e.writeErrorDocument(w, statusCode, s3Error{Code: code, Message: message})
}

// WriteNotImplemented writes a "not implemented" response
func (e *ErrorWriter) WriteNotImplemented(w http.ResponseWriter, operation string) {
	// Through the logger, not fmt.Printf: with log_format json a bare Printf
	// writes a line no log pipeline can parse, and the operation name reaches
	// here from the request.
	e.logger.WithField("operation", operation).Warn("Operation is not implemented")

	e.writeErrorDocument(w, http.StatusNotImplemented, s3Error{
		Code:     "NotImplemented",
		Message:  operation + " operation is not yet implemented",
		Resource: operation,
	})
}

// WriteNotSupportedWithEncryption writes a "not supported with encryption" response
func (e *ErrorWriter) WriteNotSupportedWithEncryption(w http.ResponseWriter, operation string) {
	e.logger.WithField("operation", operation).Warn("Operation is not supported when encryption is enabled")

	// 422 - request cannot be processed due to semantic errors
	e.writeErrorDocument(w, http.StatusUnprocessableEntity, s3Error{
		Code:     "NotSupportedWithEncryption",
		Message:  operation + " operation is not supported when encryption is enabled. Encrypted objects cannot use S3 server-side copy functionality.",
		Resource: operation,
	})
}

// WriteChecksumVerdict answers a client upload checksum failure as the S3 error
// it is and reports whether err was one. It is how a handler keeps a client
// mistake out of the 5xx it would otherwise map to (ADR 0012 D6).
//
// The verifier's error names the declaration that failed; that goes to the log,
// never into the response, where the wording is fixed per code.
func (e *ErrorWriter) WriteChecksumVerdict(w http.ResponseWriter, err error) bool {
	verdict, ok := checksumVerdict(err)
	if !ok {
		return false
	}
	e.logger.WithError(err).WithField("error_code", verdict.Code).Warn("Client upload checksum refused")
	e.writeErrorDocument(w, verdict.StatusCode, s3Error{Code: verdict.Code, Message: verdict.Message})
	return true
}
