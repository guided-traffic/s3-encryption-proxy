package utils

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"time"

	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
	"github.com/sirupsen/logrus"
)

// S3ErrorResponse represents an S3 error response
type S3ErrorResponse struct {
	XMLName   xml.Name `xml:"Error"`
	Code      string   `xml:"Code"`
	Message   string   `xml:"Message"`
	Resource  string   `xml:"Resource,omitempty"`
	RequestID string   `xml:"RequestId,omitempty"`
}

// HandleS3Error writes an S3 error response for err.
//
// Mapping lives in response.MapError — this is the only mapper in the proxy, so
// the status a client sees does not depend on which handler produced the error.
func HandleS3Error(w http.ResponseWriter, logger logrus.FieldLogger, err error, message, bucket, key string) {
	mapped := response.MapError(err)

	resource := ""
	if bucket != "" {
		resource = bucket
		if key != "" {
			resource = fmt.Sprintf("%s/%s", bucket, key)
		}
	}

	logFields := logrus.Fields{
		"message":     message,
		"status_code": mapped.StatusCode,
		"error_code":  mapped.Code,
	}
	if bucket != "" {
		logFields["bucket"] = bucket
	}
	if key != "" {
		logFields["key"] = key
	}
	entry := logger.WithFields(logFields)
	// Raw SDK text carries backend RequestID and HostID: log only, never respond with it.
	if err != nil {
		entry.WithError(err).Debug("S3 operation error detail")
	}
	if mapped.StatusCode >= http.StatusInternalServerError {
		entry.Error("S3 operation failed")
	} else {
		entry.Warn("S3 operation failed with client error")
	}

	errorResponse := S3ErrorResponse{
		Code:      mapped.Code,
		Message:   mapped.Message,
		Resource:  resource,
		RequestID: "proxy-request",
	}

	// Same document, same order and same indentation as response.ErrorWriter, and
	// marshalled before WriteHeader so a failure cannot leave a truncated body
	// behind a status that is already committed.
	xmlData, xmlErr := xml.MarshalIndent(errorResponse, "", "    ")
	if xmlErr != nil {
		logger.WithError(xmlErr).Error("Failed to marshal error response")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(mapped.StatusCode)
	if _, writeErr := w.Write(append([]byte(xml.Header), xmlData...)); writeErr != nil {
		logger.WithError(writeErr).Error("Failed to write error response")
	}
}

// cleanupTimeout bounds work that must finish after the client is gone.
const cleanupTimeout = 30 * time.Second

// CleanupContext returns a context for backend work that must outlive the
// request: aborting a multipart upload, or attaching encryption metadata to an
// object that is already stored. Using the request context there means a client
// disconnect cancels the cleanup itself, which is exactly when it is needed.
func CleanupContext(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(r.Context()), cleanupTimeout)
}
